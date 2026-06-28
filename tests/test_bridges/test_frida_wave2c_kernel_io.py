# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for FridaBridge kernel / socket / file / SQLite families.

Finding ID: FRIDA-KERNEL-IO.  All 16 methods in the kernel, socket, file
and sqlite families had 0 % test coverage at audit time.  These tests close
that gap by driving the real bridge against a minimal offline fake that
records every JS source the bridge emits and returns scripted payloads.

Each gate asserts two independent invariants:

1. **Framing invariant** -- the exact JavaScript content the bridge builds
   (address / size in decimal, protection flag, file path, SQL string, socket
   family / port) is present in the source captured by the recording session.
   This invariant catches mutations that embed the wrong argument.

2. **Parsing invariant** -- the value the bridge produces from the canned
   fake payload matches an independently computed oracle (known constant,
   ``bytes.hex()`` of a known byte sequence, exact row list, etc.).  This
   invariant catches mutations that read the wrong response field.

No real Frida runtime, real process, or kernel access is required.  All
fake session / script objects are defined in-file; no ``unittest.mock`` is
used anywhere.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import MemoryRegion, ModuleInfo, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


# ---------------------------------------------------------------------------
# Independent byte / value oracles
# ---------------------------------------------------------------------------

_KERNEL_MODULE_BASE: int = 0xFFFFF80012340000
_KERNEL_MODULE_SIZE: int = 8_192_000

_KERNEL_RANGE_BASE: int = 0xFFFFF80020000000
_KERNEL_RANGE_SIZE: int = 4096

_KERNEL_READ_ADDR: int = 0x1000
_KERNEL_READ_SIZE: int = 6
_KERNEL_READ_BYTES: bytes = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
_KERNEL_READ_HEX: str = _KERNEL_READ_BYTES.hex()

_KERNEL_WRITE_ADDR: int = 0x2000
_KERNEL_WRITE_HEX: str = "cafebabe"
_KERNEL_WRITE_BYTES: bytes = bytes.fromhex(_KERNEL_WRITE_HEX)

_KERNEL_ALLOC_SIZE: int = 4096
_KERNEL_ALLOC_ADDR: int = 0xFFFFF80030000000

_KERNEL_PROTECT_ADDR: int = 0x3000
_KERNEL_PROTECT_SIZE: int = 0x1000

_SOCKET_PORT: int = 8080
_SOCKET_HANDLE: int = 5
_SOCKET_HOST: str = "127.0.0.1"
_SOCKET_CONNECT_PORT: int = 9999

_FILE_READ_PATH: str = "/var/data/target.bin"
_FILE_READ_BYTES: bytes = bytes([0xFE, 0xED, 0xFA, 0xCE, 0x0D, 0xF0, 0xAD, 0xDE])
_FILE_READ_HEX: str = _FILE_READ_BYTES.hex()

_FILE_WRITE_PATH: str = "/var/data/out.bin"
_FILE_WRITE_HEX: str = "deadc0de"
_FILE_WRITE_BYTES: bytes = bytes.fromhex(_FILE_WRITE_HEX)

_SQLITE_DB_PATH: str = "/data/app.db"
_SQLITE_DUMP_PATH: str = "/data/dump.db"
_SQLITE_DUMP_TEXT: str = "CREATE TABLE t (id INTEGER);\nINSERT INTO t VALUES (1);\n"
_SQLITE_ROWS: list[list[object]] = [["Alice", 30], ["Bob", 25]]
_SQLITE_SQL: str = "SELECT name, age FROM users"

# ---------------------------------------------------------------------------
# Fake Frida doubles (self-contained, no unittest.mock)
# ---------------------------------------------------------------------------


class _FakeExportsSync:
    """Fake Frida RPC exports-sync proxy used by sqlite_exec tests.

    Records every SQL string passed to ``exec`` and returns a canned result.
    """

    def __init__(self, canned_result: object) -> None:
        """Initialize with a canned return value.

        Args:
            canned_result: Value returned from every ``exec`` call.
        """
        self._canned: object = canned_result
        self.exec_calls: list[str] = []

    def exec(self, sql: str) -> object:
        """Record the SQL string and return the canned result.

        Args:
            sql: SQL statement forwarded by the bridge.

        Returns:
            object: The canned result set supplied at construction time.
        """
        self.exec_calls.append(sql)
        return self._canned


class _FakeScriptKI:
    """Minimal ``frida.core.Script`` substitute for kernel / IO family tests.

    Records ``on`` / ``load`` / ``unload`` calls and supports synchronous
    message delivery to the registered handler.  Exposes ``exports_sync``
    for sqlite_exec coverage.
    """

    def __init__(self) -> None:
        """Initialize the fake script with empty call records."""
        self.source: str = ""
        self.load_calls: int = 0
        self.unload_calls: int = 0
        self._handler: Callable[..., None] | None = None
        self.exports_sync: _FakeExportsSync = _FakeExportsSync(None)

    def on(self, event: str, handler: Callable[..., None]) -> None:
        """Capture the message handler registered by the bridge.

        Args:
            event: Event name (only ``"message"`` is intercepted).
            handler: Callback invoked when a message is delivered.
        """
        if event == "message":
            self._handler = handler

    def load(self) -> None:
        """Record a load invocation."""
        self.load_calls += 1

    def unload(self) -> None:
        """Record an unload invocation."""
        self.unload_calls += 1

    def deliver(self, payload: dict[str, object], data: bytes | None = None) -> None:
        """Deliver a send-shaped payload to the registered handler synchronously.

        Args:
            payload: Payload to wrap as ``{"type": "send", "payload": ...}``.
                If ``payload["__type"] == "error"`` the message is routed as
                a Frida error message instead.
            data: Optional binary side-channel; forwarded as-is.
        """
        if self._handler is None:
            return
        if payload.get("__type") == "error":
            description = payload.get("description", "")
            self._handler({"type": "error", "description": description}, data)
            return
        self._handler({"type": "send", "payload": payload}, data)


class _RecordingSession:
    """``frida.core.Session`` substitute that records every JS source the bridge emits."""

    def __init__(self) -> None:
        """Initialize with empty script and source registries."""
        self.scripts: list[_FakeScriptKI] = []
        self.sources: list[str] = []
        self.detach_calls: int = 0

    def create_script(self, source: str, **_: object) -> _FakeScriptKI:
        """Return a new fake script, recording the JavaScript source.

        Args:
            source: JavaScript source the bridge is injecting.
            **_: Ignored keyword arguments.

        Returns:
            _FakeScriptKI: Newly created fake script associated with this source.
        """
        script = _FakeScriptKI()
        script.source = source
        self.sources.append(source)
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        """Record a detach call."""
        self.detach_calls += 1


# ---------------------------------------------------------------------------
# Bridge construction and patching helpers
# ---------------------------------------------------------------------------


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine on a fresh event loop and return its result.

    Args:
        coro: Awaitable to execute.

    Returns:
        T: Whatever the coroutine returns, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _set(target: object, name: str, value: object) -> None:
    """Set an attribute on ``target`` bypassing private-access diagnostics.

    Args:
        target: Object to mutate.
        name: Attribute name.
        value: Replacement value.
    """
    setattr(target, name, value)


def _index_set(target: object, name: str, key: object, value: object) -> None:
    """Set ``target.<name>[key] = value`` without private-usage diagnostics.

    Args:
        target: Object whose attribute holds a mapping.
        name: Attribute name.
        key: Mapping key.
        value: Mapping value.
    """
    container = cast("dict[object, object]", getattr(target, name))
    container[key] = value


def _get_dict(target: object, name: str) -> dict[object, object]:
    """Read a dict-typed private attribute cast for ``in`` / lookup checks.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        dict[object, object]: The mapping at ``target.<name>``.
    """
    return cast("dict[object, object]", getattr(target, name))


def _build_recording_bridge() -> tuple[FridaBridge, _RecordingSession]:
    """Construct a FridaBridge wired to a recording session in attached state.

    Returns:
        tuple[FridaBridge, _RecordingSession]: Bridge and its recording session.
    """
    bridge = FridaBridge()
    session = _RecordingSession()
    _set(bridge, "_session", session)
    _set(bridge, "_pid", 4321)
    bridge.state.connected = True
    bridge.state.tool_running = True
    bridge.state.process_attached = True
    bridge.state.target_pid = 4321
    return bridge, session


def _patch_execute(
    bridge: FridaBridge,
    fixed_result: dict[str, object],
) -> list[str]:
    """Replace ``_execute_script_and_wait`` with a recorder returning ``fixed_result``.

    Args:
        bridge: Bridge whose internal method to replace.
        fixed_result: Dict returned on every invocation.

    Returns:
        list[str]: List that accumulates each script source on each call.
    """
    captured: list[str] = []

    async def _fake(
        script_code: str,
        max_wait: float = 5.0,
        *,
        cancellable_id: str | None = None,
    ) -> dict[str, object]:
        del max_wait, cancellable_id
        captured.append(script_code)
        await asyncio.sleep(0)
        return dict(fixed_result)

    _set(bridge, "_execute_script_and_wait", _fake)
    return captured


# ===========================================================================
# KERNEL FAMILY
# ===========================================================================


def test_kernel_enumerate_modules_parses_name_base_size() -> None:
    """kernel_enumerate_modules parses name, hex base, and size from the canned response.

    Catches: removing the hex-prefix branch ``int(base_str, 16)`` so that
    ``int("0xfffff80012340000")`` raises ValueError instead of parsing correctly.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(
        bridge,
        {
            "type": "kernel_modules",
            "data": [
                {
                    "name": "ntkrnlmp.exe",
                    "base": hex(_KERNEL_MODULE_BASE),
                    "size": _KERNEL_MODULE_SIZE,
                },
            ],
        },
    )

    async def driver() -> list[ModuleInfo]:
        return await bridge.kernel_enumerate_modules()

    modules = _run(driver())
    assert len(modules) == 1
    m = modules[0]
    assert m.name == "ntkrnlmp.exe"
    assert m.base_address == _KERNEL_MODULE_BASE
    assert m.size == _KERNEL_MODULE_SIZE


def test_kernel_enumerate_modules_js_calls_kernel_api() -> None:
    """kernel_enumerate_modules must embed ``Kernel.enumerateModules()`` in the JS.

    Catches: substituting ``Process.enumerateModules()`` for ``Kernel.enumerateModules()``
    which would return userspace modules rather than kernel modules.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(bridge, {"type": "kernel_modules", "data": []})

    async def driver() -> list[ModuleInfo]:
        return await bridge.kernel_enumerate_modules()

    _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert "Kernel.enumerateModules()" in captured[0]
    assert "Kernel.available" in captured[0]


def test_kernel_enumerate_modules_kernel_error_raises() -> None:
    """kernel_enumerate_modules raises ToolError when the script returns a kernel_error.

    Catches: removing the ``result.get("type") == "kernel_error"`` check so
    the bridge silently returns an empty list on unsupported Kernel API.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "kernel_error", "error": "Kernel API not available"})

    async def driver() -> list[ModuleInfo]:
        return await bridge.kernel_enumerate_modules()

    with pytest.raises(ToolError, match=r"Kernel API not available"):
        _run(driver())


def test_kernel_enumerate_modules_not_attached_raises() -> None:
    """kernel_enumerate_modules raises ToolError when no session is present.

    Catches: removing the ``if self._session is None`` guard so the bridge
    crashes with AttributeError instead of raising ToolError.
    """
    bridge = FridaBridge()

    async def driver() -> list[ModuleInfo]:
        return await bridge.kernel_enumerate_modules()

    with pytest.raises(ToolError, match=r"not attached"):
        _run(driver())


def test_kernel_enumerate_ranges_embeds_protection_and_parses_region() -> None:
    """kernel_enumerate_ranges embeds the protection string in JS and parses the response.

    Catches: (1) embedding the wrong protection flag (e.g. ``'rwx'`` when
    ``'r-x'`` was requested); (2) reading ``r.protection`` from the wrong
    response field so the returned MemoryRegion has the wrong string.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(
        bridge,
        {
            "type": "kernel_ranges",
            "data": [
                {
                    "base": hex(_KERNEL_RANGE_BASE),
                    "size": _KERNEL_RANGE_SIZE,
                    "protection": "r-x",
                },
            ],
        },
    )

    async def driver() -> list[MemoryRegion]:
        return await bridge.kernel_enumerate_ranges("r-x")

    regions = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert "'r-x'" in captured[0], f"protection not embedded in JS; source={captured[0]!r}"
    assert "Kernel.enumerateRanges(" in captured[0]
    assert len(regions) == 1
    r = regions[0]
    assert r.base_address == _KERNEL_RANGE_BASE
    assert r.size == _KERNEL_RANGE_SIZE
    assert r.protection == "r-x"
    assert r.state == "committed"
    assert r.type == "kernel"


def test_kernel_enumerate_ranges_invalid_protection_raises() -> None:
    """kernel_enumerate_ranges raises ToolError for an unrecognised protection string.

    Catches: removing ``_validate_protection`` so garbage protection strings
    reach the JS template and produce undefined behaviour in the target.
    """
    bridge, _ = _build_recording_bridge()

    async def driver() -> list[MemoryRegion]:
        return await bridge.kernel_enumerate_ranges("INVALID")

    with pytest.raises(ToolError, match=r"invalid memory protection"):
        _run(driver())


def test_kernel_read_hex_oracle_and_address_size_in_js() -> None:
    """kernel_read returns the exact hex oracle and embeds address/size in JS.

    The independent oracle is ``_KERNEL_READ_BYTES.hex()`` computed before the
    bridge runs.

    Catches: (1) reading ``result["data"]`` instead of ``result["__binary"]``
    so binary data is lost; (2) embedding the wrong decimal address in JS so
    the wrong memory location is read; (3) reading size from the wrong field.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(
        bridge,
        {"type": "kernel_read", "__binary": list(_KERNEL_READ_BYTES)},
    )

    async def driver() -> str:
        return await bridge.kernel_read(_KERNEL_READ_ADDR, _KERNEL_READ_SIZE)

    result = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert str(_KERNEL_READ_ADDR) in captured[0], f"decimal address {_KERNEL_READ_ADDR} not found in JS; source={captured[0]!r}"
    assert str(_KERNEL_READ_SIZE) in captured[0], f"decimal size {_KERNEL_READ_SIZE} not found in JS; source={captured[0]!r}"
    assert "Kernel.readByteArray(" in captured[0]
    assert result == _KERNEL_READ_HEX, f"returned hex {result!r} != oracle {_KERNEL_READ_HEX!r}"


def test_kernel_read_kernel_error_raises() -> None:
    """kernel_read raises ToolError on a kernel_error script response.

    Catches: removing the error-type check so the bridge tries to extract
    ``__binary`` from an error payload and falls through to raise on missing data.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "kernel_error", "error": "Kernel API not available"})

    async def driver() -> str:
        return await bridge.kernel_read(0x1000, 4)

    with pytest.raises(ToolError, match=r"Kernel API not available"):
        _run(driver())


def test_kernel_write_embeds_address_and_hex_bytes_in_js() -> None:
    """kernel_write embeds the decimal address and expanded hex array in the JS.

    Catches: (1) using the hex address literal ``0x2000`` instead of the
    decimal ``8192`` in the JS so ``ptr(0x2000)`` becomes a JS syntax error;
    (2) expanding the wrong byte sequence into the write array.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(bridge, {"type": "kernel_written", "success": True})
    expected_hex_array = ", ".join(f"0x{b:02x}" for b in _KERNEL_WRITE_BYTES)

    async def driver() -> bool:
        return await bridge.kernel_write(_KERNEL_WRITE_ADDR, _KERNEL_WRITE_HEX)

    result = _run(driver())
    assert result is True
    assert captured, "bridge never called _execute_script_and_wait"
    assert str(_KERNEL_WRITE_ADDR) in captured[0], f"decimal address {_KERNEL_WRITE_ADDR} not found in JS; source={captured[0]!r}"
    assert expected_hex_array in captured[0], f"hex byte array {expected_hex_array!r} not found in JS; source={captured[0]!r}"
    assert "Kernel.writeByteArray(" in captured[0]


def test_kernel_write_kernel_error_raises() -> None:
    """kernel_write raises ToolError on a kernel_error script response.

    Catches: removing the error branch so the bridge returns True even when
    the Kernel API is unavailable.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "kernel_error", "error": "Kernel API not available"})

    async def driver() -> bool:
        return await bridge.kernel_write(0x1000, "deadbeef")

    with pytest.raises(ToolError, match=r"Kernel API not available"):
        _run(driver())


def test_kernel_alloc_parses_hex_address_from_response() -> None:
    """kernel_alloc parses the hex address string returned by the kernel script.

    The oracle is the integer constant ``_KERNEL_ALLOC_ADDR`` compared after
    the bridge converts ``hex(_KERNEL_ALLOC_ADDR)`` back via ``int(addr, 16)``.

    Catches: switching from ``int(addr_str, 16)`` to ``int(addr_str)`` so that
    the hex address string is parsed incorrectly and raises ValueError.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(
        bridge,
        {"type": "kernel_alloc", "address": hex(_KERNEL_ALLOC_ADDR)},
    )

    async def driver() -> int:
        return await bridge.kernel_alloc(_KERNEL_ALLOC_SIZE)

    addr = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert str(_KERNEL_ALLOC_SIZE) in captured[0]
    assert "Kernel.alloc(" in captured[0]
    assert addr == _KERNEL_ALLOC_ADDR, f"parsed address 0x{addr:x} != oracle 0x{_KERNEL_ALLOC_ADDR:x}"


def test_kernel_alloc_kernel_error_raises() -> None:
    """kernel_alloc raises ToolError on a kernel_error script response.

    Catches: removing the error check so the bridge tries to parse the
    ``address`` field from an error payload and returns 0 silently.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "kernel_error", "error": "Kernel API not available"})

    async def driver() -> int:
        return await bridge.kernel_alloc(4096)

    with pytest.raises(ToolError, match=r"Kernel API not available"):
        _run(driver())


def test_kernel_protect_embeds_address_size_protection_in_js() -> None:
    """kernel_protect embeds address, size, and protection flag in the JS.

    Catches: (1) embedding the wrong decimal address; (2) embedding the wrong
    protection string so a different protection is applied than requested.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(bridge, {"type": "kernel_protected", "success": True})

    async def driver() -> bool:
        return await bridge.kernel_protect(_KERNEL_PROTECT_ADDR, _KERNEL_PROTECT_SIZE, "r-x")

    result = _run(driver())
    assert result is True
    assert captured, "bridge never called _execute_script_and_wait"
    assert str(_KERNEL_PROTECT_ADDR) in captured[0], f"address {_KERNEL_PROTECT_ADDR} not in JS; source={captured[0]!r}"
    assert str(_KERNEL_PROTECT_SIZE) in captured[0], f"size {_KERNEL_PROTECT_SIZE} not in JS; source={captured[0]!r}"
    assert "'r-x'" in captured[0], f"protection 'r-x' not in JS; source={captured[0]!r}"
    assert "Kernel.protect(" in captured[0]


def test_kernel_protect_invalid_protection_raises() -> None:
    """kernel_protect raises ToolError for an unrecognised protection string.

    Catches: removing ``_validate_protection`` so the bridge builds JS with
    an invalid protection value that Frida rejects at runtime.
    """
    bridge, _ = _build_recording_bridge()

    async def driver() -> bool:
        return await bridge.kernel_protect(0x1000, 0x1000, "BADPROT")

    with pytest.raises(ToolError, match=r"invalid memory protection"):
        _run(driver())


def test_kernel_protect_kernel_error_raises() -> None:
    """kernel_protect raises ToolError on a kernel_error script response.

    Catches: removing the error check so the bridge returns True even when
    kernel protection change fails.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "kernel_error", "error": "Kernel API not available"})

    async def driver() -> bool:
        return await bridge.kernel_protect(0x1000, 0x1000, "r-x")

    with pytest.raises(ToolError, match=r"Kernel API not available"):
        _run(driver())


# ===========================================================================
# SOCKET FAMILY
# ===========================================================================


def test_socket_listen_embeds_port_family_and_returns_script_id() -> None:
    """socket_listen embeds port / family in JS and returns a stored script_id.

    socket_listen does not use ``_execute_script_and_wait``; it creates the
    script directly.  The recording session captures the JS source.

    Catches: (1) embedding the wrong port literal so the listener binds the
    wrong port; (2) embedding the wrong family string; (3) not registering the
    returned script_id in ``_scripts`` so subsequent unload calls cannot find it.
    """
    bridge, session = _build_recording_bridge()

    async def driver() -> str:
        return await bridge.socket_listen(_SOCKET_PORT, "ipv4")

    script_id = _run(driver())
    assert isinstance(script_id, str)
    assert len(session.sources) == 1
    source = session.sources[0]
    assert "Socket.listen(" in source, f"Socket.listen not in JS; source={source!r}"
    assert str(_SOCKET_PORT) in source, f"port {_SOCKET_PORT} not in JS; source={source!r}"
    assert "'ipv4'" in source, f"family 'ipv4' not in JS; source={source!r}"
    scripts = _get_dict(bridge, "_scripts")
    assert script_id in scripts, f"script_id {script_id!r} not stored in _scripts"


def test_socket_listen_invalid_family_raises() -> None:
    """socket_listen raises ToolError for an unrecognised socket family.

    Catches: removing ``_validate_socket_family`` so invalid family strings
    reach the JS template and cause a Frida runtime error in the target.
    """
    bridge, _ = _build_recording_bridge()

    async def driver() -> str:
        return await bridge.socket_listen(8080, "bluetooth")

    with pytest.raises(ToolError, match=r"socket"):
        _run(driver())


def test_socket_listen_not_attached_raises() -> None:
    """socket_listen raises ToolError when no session is present.

    Catches: removing the ``if self._session is None`` guard.
    """
    bridge = FridaBridge()

    async def driver() -> str:
        return await bridge.socket_listen(8080)

    with pytest.raises(ToolError, match=r"not attached"):
        _run(driver())


def test_socket_connect_embeds_host_port_family_and_returns_dict() -> None:
    """socket_connect embeds host / port / family in JS and returns the response dict.

    Catches: (1) embedding the wrong host or port in JS so the connection
    targets the wrong endpoint; (2) returning an empty dict instead of the
    full response dict that includes ``host`` and ``port`` fields.
    """
    bridge, _ = _build_recording_bridge()
    canned: dict[str, object] = {
        "type": "socket_connected",
        "host": _SOCKET_HOST,
        "port": _SOCKET_CONNECT_PORT,
    }
    captured = _patch_execute(bridge, canned)

    async def driver() -> dict[str, object]:
        return await bridge.socket_connect(_SOCKET_HOST, _SOCKET_CONNECT_PORT, "ipv4")

    result = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert f"'{_SOCKET_HOST}'" in captured[0], f"host {_SOCKET_HOST!r} not in JS; source={captured[0]!r}"
    assert str(_SOCKET_CONNECT_PORT) in captured[0], f"port {_SOCKET_CONNECT_PORT} not in JS; source={captured[0]!r}"
    assert "'ipv4'" in captured[0], f"family 'ipv4' not in JS; source={captured[0]!r}"
    assert result.get("host") == _SOCKET_HOST
    assert result.get("port") == _SOCKET_CONNECT_PORT


def test_socket_connect_socket_error_raises() -> None:
    """socket_connect raises ToolError when the script returns a socket_error.

    Catches: removing the error-type check so the bridge returns the error
    dict as a successful result.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "socket_error", "error": "connection refused"})

    async def driver() -> dict[str, object]:
        return await bridge.socket_connect("10.0.0.1", 80)

    with pytest.raises(ToolError, match=r"socket"):
        _run(driver())


def test_socket_type_embeds_handle_and_returns_type_string() -> None:
    """socket_type embeds the handle fd in JS and parses the type string from the response.

    Catches: (1) embedding the wrong handle value in JS so Socket.type queries
    the wrong fd; (2) returning the raw response dict instead of the ``value``
    string field.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(bridge, {"type": "socket_type", "value": "tcp"})

    async def driver() -> str:
        return await bridge.socket_type(_SOCKET_HANDLE)

    result = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert str(_SOCKET_HANDLE) in captured[0], f"handle {_SOCKET_HANDLE} not in JS; source={captured[0]!r}"
    assert "Socket.type(" in captured[0]
    assert result == "tcp", f"type string wrong: {result!r}"


def test_socket_type_socket_error_raises() -> None:
    """socket_type raises ToolError when the script returns a socket_error.

    Catches: removing the error-type check so the bridge returns an empty
    string on socket_error responses.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "socket_error", "error": "bad descriptor"})

    async def driver() -> str:
        return await bridge.socket_type(99)

    with pytest.raises(ToolError, match=r"socket"):
        _run(driver())


def test_socket_local_address_returns_address_dict_from_data_field() -> None:
    """socket_local_address returns the dict from the ``data`` response field.

    Catches: reading ``result`` directly instead of ``result.get("data")``
    so the returned dict contains the outer envelope instead of the address.
    """
    bridge, _ = _build_recording_bridge()
    addr_data: dict[str, object] = {"ip": "127.0.0.1", "port": 12345}
    captured = _patch_execute(bridge, {"type": "socket_addr", "data": addr_data})

    async def driver() -> dict[str, object]:
        return await bridge.socket_local_address(_SOCKET_HANDLE)

    result = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert "Socket.localAddress(" in captured[0]
    assert str(_SOCKET_HANDLE) in captured[0]
    assert result == addr_data, f"returned dict {result!r} != oracle {addr_data!r}"


def test_socket_peer_address_returns_peer_dict_from_data_field() -> None:
    """socket_peer_address returns the dict from the ``data`` response field.

    Catches: reading the wrong response field so the peer address dict is lost
    and an empty dict is returned.
    """
    bridge, _ = _build_recording_bridge()
    peer_data: dict[str, object] = {"ip": "192.168.1.1", "port": 80}
    captured = _patch_execute(bridge, {"type": "socket_addr", "data": peer_data})

    async def driver() -> dict[str, object]:
        return await bridge.socket_peer_address(_SOCKET_HANDLE)

    result = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert "Socket.peerAddress(" in captured[0]
    assert str(_SOCKET_HANDLE) in captured[0]
    assert result == peer_data, f"returned dict {result!r} != oracle {peer_data!r}"


# ===========================================================================
# FILE FAMILY
# ===========================================================================


def test_file_read_target_returns_exact_hex_oracle() -> None:
    """file_read_target returns the exact hex encoding of the canned binary payload.

    The oracle ``_FILE_READ_HEX`` is computed from ``_FILE_READ_BYTES.hex()``
    before the bridge runs; it is independent of any production code path.

    Catches: (1) reading ``result["data"]`` instead of ``result["__binary"]``
    so the binary payload is lost; (2) incorrect hex encoding (e.g. reversed
    bytes or wrong format string).
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(
        bridge,
        {"type": "file_read", "__binary": list(_FILE_READ_BYTES)},
    )

    async def driver() -> str:
        return await bridge.file_read_target(_FILE_READ_PATH)

    result = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert result == _FILE_READ_HEX, f"returned hex {result!r} != oracle {_FILE_READ_HEX!r}"


def test_file_read_target_embeds_path_and_rb_mode_in_js() -> None:
    """file_read_target embeds the file path and read-binary mode in the JS.

    Catches: (1) embedding the wrong path so a different file is read;
    (2) using ``'r'`` (text) instead of ``'rb'`` (binary) mode so binary
    data is corrupted in the target's JS runtime.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(bridge, {"type": "file_read", "__binary": []})

    async def driver() -> str:
        return await bridge.file_read_target(_FILE_READ_PATH)

    _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert f"'{_FILE_READ_PATH}'" in captured[0], f"path {_FILE_READ_PATH!r} not in JS; source={captured[0]!r}"
    assert "'rb'" in captured[0], f"read-binary mode not in JS; source={captured[0]!r}"
    assert "new File(" in captured[0]


def test_file_read_target_file_error_raises() -> None:
    """file_read_target raises ToolError when the script returns a file_error.

    Catches: removing the error-type check so the bridge tries to extract
    ``__binary`` from an error payload and returns garbage.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "file_error", "error": "no such file"})

    async def driver() -> str:
        return await bridge.file_read_target("/missing/file.bin")

    with pytest.raises(ToolError, match=r"file"):
        _run(driver())


def test_file_write_target_embeds_path_and_hex_bytes_in_js() -> None:
    """file_write_target embeds the path and expanded hex byte array in the JS.

    Catches: (1) embedding the wrong path; (2) expanding the wrong byte
    sequence into the write array so different bytes are written to the target.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(bridge, {"type": "file_written", "success": True})
    expected_hex_array = ", ".join(f"0x{b:02x}" for b in _FILE_WRITE_BYTES)

    async def driver() -> bool:
        return await bridge.file_write_target(_FILE_WRITE_PATH, _FILE_WRITE_HEX)

    result = _run(driver())
    assert result is True
    assert captured, "bridge never called _execute_script_and_wait"
    assert f"'{_FILE_WRITE_PATH}'" in captured[0], f"path {_FILE_WRITE_PATH!r} not in JS; source={captured[0]!r}"
    assert expected_hex_array in captured[0], f"hex array {expected_hex_array!r} not in JS; source={captured[0]!r}"
    assert "'wb'" in captured[0], f"write-binary mode not in JS; source={captured[0]!r}"


def test_file_write_target_file_error_raises() -> None:
    """file_write_target raises ToolError when the script returns a file_error.

    Catches: removing the error check so the bridge returns True even when
    the file write fails in the target process.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "file_error", "error": "permission denied"})

    async def driver() -> bool:
        return await bridge.file_write_target("/readonly/file.bin", "deadbeef")

    with pytest.raises(ToolError, match=r"file"):
        _run(driver())


# ===========================================================================
# SQLITE FAMILY
# ===========================================================================


def test_sqlite_open_registers_script_id_and_emits_correct_js() -> None:
    """sqlite_open registers the script_id in ``_scripts`` and embeds the path in JS.

    sqlite_open uses ``_make_payload_waiter`` rather than
    ``_execute_script_and_wait``; the recording session captures the JS source
    and the task-based driver delivers the ``sqlite_opened`` acknowledgement.

    Catches: (1) not registering the script_id so sqlite_exec cannot look it
    up; (2) embedding the wrong path so the wrong database is opened; (3) not
    emitting ``rpc.exports`` so sqlite_exec RPC calls fail.
    """
    bridge, session = _build_recording_bridge()

    async def driver() -> str:
        task = asyncio.create_task(bridge.sqlite_open(_SQLITE_DB_PATH))
        await asyncio.sleep(0)
        for _ in range(80):
            if session.scripts and session.scripts[-1].load_calls > 0:
                break
            await asyncio.sleep(0.01)
        assert session.scripts, "sqlite_open did not create a script"
        session.scripts[-1].deliver({"type": "sqlite_opened", "success": True})
        return await task

    script_id = _run(driver())
    assert isinstance(script_id, str)
    assert len(session.sources) == 1
    source = session.sources[0]
    assert f"'{_SQLITE_DB_PATH}'" in source, f"db path {_SQLITE_DB_PATH!r} not in JS; source={source!r}"
    assert "SqliteDatabase.open(" in source
    assert "rpc.exports" in source
    scripts = _get_dict(bridge, "_scripts")
    assert script_id in scripts, f"script_id {script_id!r} not registered in _scripts"


def test_sqlite_open_sqlite_error_raises() -> None:
    """sqlite_open raises ToolError when the script reports a sqlite_error.

    Catches: removing the ``sqlite_error`` check in the message loop so the
    bridge returns a script_id even when the database cannot be opened.
    """
    bridge, session = _build_recording_bridge()

    async def driver() -> str:
        task = asyncio.create_task(bridge.sqlite_open("/data/missing.db"))
        await asyncio.sleep(0)
        for _ in range(80):
            if session.scripts and session.scripts[-1].load_calls > 0:
                break
            await asyncio.sleep(0.01)
        assert session.scripts, "sqlite_open did not create a script"
        session.scripts[-1].deliver({"type": "sqlite_error", "error": "no such file"})
        return await task

    with pytest.raises(ToolError, match=r"SQLite"):
        _run(driver())


def test_sqlite_open_not_attached_raises() -> None:
    """sqlite_open raises ToolError when no session is present.

    Catches: removing the ``if self._session is None`` guard.
    """
    bridge = FridaBridge()

    async def driver() -> str:
        return await bridge.sqlite_open("/data/test.db")

    with pytest.raises(ToolError, match=r"not attached"):
        _run(driver())


def test_sqlite_exec_passes_exact_sql_and_returns_canned_rows() -> None:
    """sqlite_exec passes the exact SQL string to exports_sync.exec and returns rows.

    The canned rows ``_SQLITE_ROWS`` are the independent oracle; the test also
    asserts that ``exec_calls[0]`` is exactly ``_SQLITE_SQL`` so any mutation
    that passes the wrong SQL to the RPC is caught.

    Catches: (1) calling ``exports_sync.dump`` instead of ``exports_sync.exec``;
    (2) passing an empty string or the wrong sql to ``exec``; (3) discarding
    the result and returning None.
    """
    bridge, _ = _build_recording_bridge()
    script_id = "deadc0de"
    fake_script = _FakeScriptKI()
    fake_script.exports_sync = _FakeExportsSync(_SQLITE_ROWS)
    _index_set(bridge, "_scripts", script_id, fake_script)

    async def driver() -> object:
        return await bridge.sqlite_exec(script_id, _SQLITE_SQL)

    result = _run(driver())
    assert result == _SQLITE_ROWS, f"returned rows {result!r} != oracle {_SQLITE_ROWS!r}"
    assert fake_script.exports_sync.exec_calls == [_SQLITE_SQL], (
        f"exec called with wrong SQL; calls={fake_script.exports_sync.exec_calls!r}"
    )


def test_sqlite_exec_unknown_script_id_raises() -> None:
    """sqlite_exec raises ToolError for a script_id not registered in _scripts.

    Catches: removing the ``if script_id not in self._scripts`` guard so the
    bridge crashes with KeyError instead of raising ToolError.
    """
    bridge, _ = _build_recording_bridge()

    async def driver() -> object:
        return await bridge.sqlite_exec("nonexistent-id", "SELECT 1")

    with pytest.raises(ToolError, match=r"script not found"):
        _run(driver())


def test_sqlite_dump_returns_dump_string_and_embeds_path_in_js() -> None:
    """sqlite_dump returns the dump string from the response and embeds the path in JS.

    Catches: (1) reading ``result["dump"]`` instead of ``result["data"]`` so
    the dump text is always empty; (2) embedding the wrong path so the wrong
    database is dumped.
    """
    bridge, _ = _build_recording_bridge()
    captured = _patch_execute(
        bridge,
        {"type": "sqlite_dump", "data": _SQLITE_DUMP_TEXT},
    )

    async def driver() -> str:
        return await bridge.sqlite_dump(_SQLITE_DUMP_PATH)

    result = _run(driver())
    assert captured, "bridge never called _execute_script_and_wait"
    assert f"'{_SQLITE_DUMP_PATH}'" in captured[0], f"path {_SQLITE_DUMP_PATH!r} not in JS; source={captured[0]!r}"
    assert "SqliteDatabase.open(" in captured[0]
    assert "db.dump()" in captured[0]
    assert result == _SQLITE_DUMP_TEXT, f"dump string {result!r} != oracle {_SQLITE_DUMP_TEXT!r}"


def test_sqlite_dump_sqlite_error_raises() -> None:
    """sqlite_dump raises ToolError when the script returns a sqlite_error.

    Catches: removing the error-type check so the bridge returns the error
    message string as the dump output.
    """
    bridge, _ = _build_recording_bridge()
    _patch_execute(bridge, {"type": "sqlite_error", "error": "corrupt database"})

    async def driver() -> str:
        return await bridge.sqlite_dump("/data/bad.db")

    with pytest.raises(ToolError, match=r"SQLite"):
        _run(driver())
