# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Standalone real Windows named-pipe server for NamedPipeClient tests.

This module is intentionally free of any pytest / Intellicrack imports so it
can be launched as a dedicated child process (``python -m
tests._helpers.realcov_pipe_server <pipe_name> <mode>``) without dragging the
test harness into the child. The server hosts one duplex byte-stream named
pipe, accepts a single client, and services length-prefixed JSON request
frames according to the selected mode, replying with the matching frames. All
I/O uses the genuine Win32 named-pipe APIs so the client under test exercises
the real kernel transport. Running in a separate OS process keeps the blocking
kernel I/O off the client's GIL.
"""

from __future__ import annotations

import ctypes
import json
import sys
import time
from ctypes import wintypes
from typing import Any, cast


PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_BUF_SIZE = 1 << 16
LENGTH_PREFIX_SIZE = 4
CHUNK_SIZE = 65536
ERROR_PIPE_CONNECTED = 535
INVALID_HANDLES = frozenset({0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})

MODE_ECHO = "echo"
MODE_INDEX = "index"
MODE_BLOB = "blob"
MODE_EVENT_THEN_ECHO = "event_then_echo"
MODE_DROP_AFTER_ONE = "drop_after_one"
MODE_DELAYED_EVENT = "delayed_event"
MODE_ECHO_SUCCESS = "echo_success"

BLOB_PAYLOAD = "A1b2C3" * 40000
EVENT_NAME = "breakpoint_hit"
EVENT_ADDRESS = 0x401000
IDLE_DELAY_SECONDS = 2.0


def _kernel32() -> ctypes.WinDLL:
    """Return a kernel32 binding with the server-side pipe entry points typed.

    Returns:
        ctypes.WinDLL: Typed ``kernel32`` library.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateNamedPipeW.restype = wintypes.HANDLE
    k32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    k32.ConnectNamedPipe.restype = wintypes.BOOL
    k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    k32.ReadFile.restype = wintypes.BOOL
    k32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    k32.WriteFile.restype = wintypes.BOOL
    k32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    k32.DisconnectNamedPipe.restype = wintypes.BOOL
    k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    k32.FlushFileBuffers.restype = wintypes.BOOL
    k32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    return k32


def _read_exact(k32: ctypes.WinDLL, handle: int, size: int) -> bytes | None:
    """Read exactly ``size`` bytes from ``handle`` via real ``ReadFile``.

    Args:
        k32: Typed kernel32 binding.
        handle: Connected server pipe handle.
        size: Number of bytes to read.

    Returns:
        bytes | None: The bytes read, or ``None`` if the pipe closed/broke.
    """
    out = bytearray()
    while len(out) < size:
        remaining = size - len(out)
        chunk_size = min(CHUNK_SIZE, remaining)
        buf = ctypes.create_string_buffer(chunk_size)
        read = wintypes.DWORD(0)
        ok = k32.ReadFile(handle, buf, chunk_size, ctypes.byref(read), None)
        if not ok or read.value == 0:
            return None
        out.extend(buf.raw[: read.value])
    return bytes(out)


def _write_frame(k32: ctypes.WinDLL, handle: int, payload: dict[str, Any]) -> None:
    """Write a single length-prefixed JSON frame via real ``WriteFile``.

    Args:
        k32: Typed kernel32 binding.
        handle: Connected server pipe handle.
        payload: Frame body to serialise and transmit.
    """
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    data = len(body).to_bytes(LENGTH_PREFIX_SIZE, "little", signed=False) + body
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + CHUNK_SIZE]
        written = wintypes.DWORD(0)
        if not k32.WriteFile(handle, chunk, len(chunk), ctypes.byref(written), None):
            return
        offset += written.value


def _read_frame(k32: ctypes.WinDLL, handle: int) -> dict[str, Any] | None:
    """Read one length-prefixed JSON frame from the connected client.

    Args:
        k32: Typed kernel32 binding.
        handle: Connected server pipe handle.

    Returns:
        dict[str, Any] | None: Decoded request frame, or ``None`` on
        disconnect / malformed frame.
    """
    prefix = _read_exact(k32, handle, LENGTH_PREFIX_SIZE)
    if prefix is None:
        return None
    length = int.from_bytes(prefix, "little", signed=False)
    body = _read_exact(k32, handle, length)
    if body is None:
        return None
    decoded: object = json.loads(body.decode("utf-8"))
    return cast("dict[str, Any]", decoded) if isinstance(decoded, dict) else None


def _build_replies(mode: str, frame: dict[str, Any]) -> list[dict[str, Any]]:
    """Build the response frames for a single request under ``mode``.

    Args:
        mode: Server behaviour selector.
        frame: Decoded client request frame.

    Returns:
        list[dict[str, Any]]: Frames to write back to the client.
    """
    rid = int(frame["id"])
    if mode in {MODE_DROP_AFTER_ONE, MODE_ECHO_SUCCESS}:
        return [
            {
                "id": rid,
                "type": "response",
                "success": True,
                "result": {"echo_command": frame.get("command")},
            },
        ]
    if mode == MODE_INDEX:
        params: object = frame.get("params")
        index = -1
        if isinstance(params, dict):
            raw_index = cast("dict[str, Any]", params).get("index")
            if isinstance(raw_index, int):
                index = raw_index
        return [{"id": rid, "type": "response", "ok": True, "index": index}]
    if mode == MODE_BLOB:
        return [{"id": rid, "type": "response", "ok": True, "blob": BLOB_PAYLOAD}]
    echo = {
        "id": rid,
        "type": "response",
        "ok": True,
        "echo_command": frame.get("command"),
        "echo_params": frame.get("params"),
    }
    if mode == MODE_EVENT_THEN_ECHO:
        event = {"type": "event", "name": EVENT_NAME, "address": EVENT_ADDRESS}
        return [event, echo]
    return [echo]


def _serve_connection(k32: ctypes.WinDLL, handle: int, mode: str) -> None:
    """Accept one client and service its framed requests until disconnect.

    Args:
        k32: Typed kernel32 binding.
        handle: Server pipe handle to accept on and serve.
        mode: Server behaviour selector (echo / index / blob / event+echo /
            delayed_event).
    """
    if not k32.ConnectNamedPipe(handle, None) and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
        return
    request_count = 0
    while True:
        request = _read_frame(k32, handle)
        if request is None:
            break
        request_count += 1
        for reply in _build_replies(mode, request):
            _write_frame(k32, handle, reply)
        if mode == MODE_DROP_AFTER_ONE:
            # Block until the client has drained the reply before the server
            # tears the pipe down. Without this, the ``DisconnectNamedPipe`` in
            # :func:`serve` would forcibly discard the still-buffered reply and
            # the client would observe a read failure instead of the response.
            k32.FlushFileBuffers(handle)
            break
        if mode == MODE_DELAYED_EVENT and request_count == 1:
            # Stay silent for longer than a short client io_timeout before
            # pushing an unsolicited event, reproducing the legitimate idle
            # gap between debugger events (F16). The client must not treat
            # this silence as a fatal read timeout.
            k32.FlushFileBuffers(handle)
            time.sleep(IDLE_DELAY_SECONDS)
            _write_frame(k32, handle, {"type": "event", "name": EVENT_NAME, "address": EVENT_ADDRESS})


def serve(pipe_name: str, mode: str) -> int:
    """Serve one client connection on a real named pipe.

    Args:
        pipe_name: Fully-qualified named-pipe path to host.
        mode: Server behaviour selector (echo / index / blob / event+echo).

    Returns:
        int: ``0`` on a clean run, ``1`` if the endpoint could not be created.
    """
    k32 = _kernel32()
    handle: int = k32.CreateNamedPipeW(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        PIPE_BUF_SIZE,
        PIPE_BUF_SIZE,
        0,
        None,
    )
    if handle in INVALID_HANDLES:
        return 1
    try:
        _serve_connection(k32, handle, mode)
    finally:
        k32.DisconnectNamedPipe(handle)
        k32.CloseHandle(handle)
    return 0


def main() -> int:
    """Command-line entry point: ``<pipe_name> <mode>``.

    Returns:
        int: Process exit code.
    """
    expected_args = 3
    return 2 if len(sys.argv) != expected_args else serve(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    sys.exit(main())
