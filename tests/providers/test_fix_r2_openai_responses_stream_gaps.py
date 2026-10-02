# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 26: the built-in OpenAI Responses stream keeps tool-search items for replay and hangs up when cancelled.

Both gates drive the real :class:`OpenAIProvider` through the real ``openai`` SDK. The first streams a turn in which the model searched
its deferred tools and reads what the provider kept for the next request. The second serves the stream from a bare socket, cancels
after the first text delta, and watches that socket: a stream the provider closed ends the connection, and one it abandoned leaves it
open with the rest of the response unread.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from typing import TYPE_CHECKING, Any, Final

from intellicrack.core.types import Message, ProviderCredentials, ReasoningKind
from intellicrack.providers.openai import OpenAIProvider
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import Mapping


_MODEL: Final[str] = "gpt-5.2"
_API_KEY: Final[str] = "sk-proj-loopbackStreamGapsKey0123456789"
_HANGUP_WAIT_S: Final[float] = 5.0
_ACCEPT_WAIT_S: Final[float] = 30.0


def _response_object(status: str) -> dict[str, Any]:
    """Build a Responses ``response`` object.

    Args:
        status: The response status.

    Returns:
        dict[str, Any]: The object.
    """
    return {
        "id": "resp_loopback",
        "object": "response",
        "created_at": 1_760_000_000,
        "model": _MODEL,
        "status": status,
        "output": [],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
    }


def _text_delta(sequence: int, text: str) -> dict[str, Any]:
    """Build one ``response.output_text.delta`` event.

    Args:
        sequence: The event's sequence number.
        text: The delta.

    Returns:
        dict[str, Any]: The event.
    """
    return {
        "type": "response.output_text.delta",
        "sequence_number": sequence,
        "item_id": "msg_1",
        "output_index": 1,
        "content_index": 0,
        "delta": text,
        "logprobs": [],
    }


def test_streamed_tool_search_items_are_kept_for_replay() -> None:
    """The ``tool_search_call`` and ``tool_search_output`` items of a streamed turn are kept verbatim, as the dialect path keeps them."""
    search_call = {"id": "tsc_1", "type": "tool_search_call", "status": "completed", "arguments": {"query": "spawn"}, "execution": "server"}
    search_output = {
        "id": "tso_1",
        "type": "tool_search_output",
        "status": "completed",
        "execution": "server",
        "tools": [{"type": "function", "name": "spawn", "namespace": "frida", "parameters": {"type": "object"}}],
    }
    events = [
        {"type": "response.created", "sequence_number": 0, "response": _response_object("in_progress")},
        {"type": "response.output_item.done", "sequence_number": 1, "output_index": 0, "item": search_call},
        {"type": "response.output_item.done", "sequence_number": 2, "output_index": 1, "item": search_output},
        _text_delta(3, "found it"),
        {"type": "response.completed", "sequence_number": 4, "response": _response_object("completed")},
    ]
    server = ScriptedHTTPServer({
        ("GET", "/v1/models"): json_response({
            "object": "list",
            "data": [{"id": _MODEL, "object": "model", "created": 0, "owned_by": "o"}],
        }),
        ("POST", "/v1/responses"): sse_response(events),
    })

    async def run() -> OpenAIProvider:
        """Stream one turn.

        Returns:
            OpenAIProvider: The provider, holding what it captured.
        """
        provider = OpenAIProvider()
        await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{server.origin}/v1"))
        _ = [chunk async for chunk in provider.chat_stream([Message(role="user", content="spawn")], _MODEL)]
        return provider

    try:
        provider = asyncio.run(run())
    finally:
        server.close()
    kept = [item for item in provider.get_pending_reasoning() if item.kind is ReasoningKind.PROVIDER_ITEM]
    assert [item.item_id for item in kept] == ["tsc_1", "tso_1"]
    payloads: list[Mapping[str, object]] = [item.payload or {} for item in kept]
    assert [payload.get("type") for payload in payloads] == ["tool_search_call", "tool_search_output"]


class _HangupWatchingServer:
    """Serves one streamed Responses turn from a bare socket and reports whether the client hung up.

    The first text delta goes out at once; the second only once the test has cancelled. The server then waits for the client to close
    its end.

    Attributes:
        cancelled: Set by the test once it has asked the provider to cancel.
        watched: Set once the server has decided whether the client hung up.
        hung_up: Whether the client closed the connection within the wait.
    """

    cancelled: threading.Event
    watched: threading.Event
    hung_up: bool | None

    def __init__(self) -> None:
        """Listen on an ephemeral loopback port."""
        self.cancelled = threading.Event()
        self.hung_up = None
        self._streamed = threading.Event()
        self.watched = self._streamed
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._thread = threading.Thread(target=self._serve, name="hangup-watcher", daemon=True)
        self._thread.start()

    @property
    def origin(self) -> str:
        """The server origin.

        Returns:
            str: ``http://127.0.0.1:<port>``.
        """
        return f"http://127.0.0.1:{self._listener.getsockname()[1]}"

    @staticmethod
    def _frame(event: dict[str, Any]) -> bytes:
        """Frame one event as an HTTP chunk carrying one SSE message.

        Args:
            event: The event.

        Returns:
            bytes: The chunk.
        """
        payload = f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
        return f"{len(payload):x}\r\n".encode() + payload + b"\r\n"

    def _serve(self) -> None:
        """Accept connections until the streamed turn has been watched."""
        self._listener.settimeout(_ACCEPT_WAIT_S)
        while self.hung_up is None:
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                return
            threading.Thread(target=self._answer, args=(connection,), daemon=True).start()
            self._streamed.wait(_ACCEPT_WAIT_S / 10)

    @staticmethod
    def _read_request(connection: socket.socket, buffered: bytes) -> tuple[bytes, bytes] | None:
        """Read one request's head and body.

        Args:
            connection: The client connection.
            buffered: Bytes already read past the previous request.

        Returns:
            tuple[bytes, bytes] | None: The request line and whatever followed the body, or ``None`` once the client closed.
        """
        received = buffered
        while b"\r\n\r\n" not in received:
            more = connection.recv(65536)
            if not more:
                return None
            received += more
        head, _, rest = received.partition(b"\r\n\r\n")
        length = next(
            (int(line.split(b":", 1)[1]) for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")),
            0,
        )
        while len(rest) < length:
            rest += connection.recv(65536)
        return head.split(b"\r\n", 1)[0], rest[length:]

    def _answer(self, connection: socket.socket) -> None:
        """Answer the model listing, then stream the turn and watch for the hang-up.

        Args:
            connection: The client connection.
        """
        with connection:
            buffered = b""
            while (request := self._read_request(connection, buffered)) is not None:
                line, buffered = request
                if not line.startswith(b"POST"):
                    listing = json.dumps({"object": "list", "data": [{"id": _MODEL, "object": "model", "created": 0, "owned_by": "o"}]})
                    connection.sendall(
                        f"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {len(listing)}\r\n\r\n{listing}".encode(),
                    )
                    continue
                self._stream(connection)
                return

    def _stream(self, connection: socket.socket) -> None:
        """Stream the turn, then wait for the client to close its end.

        Args:
            connection: The client connection.
        """
        connection.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n")
        connection.sendall(self._frame({"type": "response.created", "sequence_number": 0, "response": _response_object("in_progress")}))
        connection.sendall(self._frame(_text_delta(1, "first ")))
        _ = self.cancelled.wait(_ACCEPT_WAIT_S)
        connection.sendall(self._frame(_text_delta(2, "second ")))
        connection.settimeout(_HANGUP_WAIT_S)
        try:
            self.hung_up = connection.recv(65536) == b""
        except TimeoutError:
            self.hung_up = False
        except ConnectionResetError:
            self.hung_up = True
        self._streamed.set()

    def close(self) -> None:
        """Stop listening and wait for the watcher to finish."""
        self.cancelled.set()
        self._thread.join(_ACCEPT_WAIT_S + _HANGUP_WAIT_S)
        self._listener.close()


def test_cancel_closes_the_sdk_stream() -> None:
    """Cancelling mid-stream closes the connection instead of abandoning it with the rest of the response unread."""
    server = _HangupWatchingServer()

    async def run() -> list[str]:
        """Stream until the first delta, cancel, and finish the loop.

        Returns:
            list[str]: The chunks yielded.
        """
        provider = OpenAIProvider()
        await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{server.origin}/v1"))
        assert provider.client is not None
        provider.client = provider.client.with_options(max_retries=0)
        chunks: list[str] = []
        async for chunk in provider.chat_stream([Message(role="user", content="go")], _MODEL):
            chunks.append(chunk)
            await provider.cancel_request()
            server.cancelled.set()
        verdict = await asyncio.to_thread(server.watched.wait, _ACCEPT_WAIT_S)
        assert verdict, "the server never finished watching the stream"
        assert provider.client is not None
        return chunks

    try:
        chunks = asyncio.run(run())
    finally:
        server.close()
    assert chunks == ["first "]
    assert server.hung_up is True
