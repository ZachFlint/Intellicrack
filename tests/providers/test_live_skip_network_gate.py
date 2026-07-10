# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for the providers conftest network-unavailable skip classifier.

The live provider tests issue real, billable calls against external endpoints.
When a run has no outbound network (for example the offline Docker sandbox with
``--network none``) those calls fail with a DNS-resolution / connection error
rather than exercising the provider. ``conftest._network_unavailable_reason``
classifies that specific, environment-driven failure so the ``pytest_runtest_call``
wrapper can turn it into a skip instead of a false negative, while every other
failure - including a genuine product connection bug against a reachable host -
still propagates. These tests pin that classifier to real exception chains.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, cast

import httpx

from tests.providers import conftest as providers_conftest


if TYPE_CHECKING:
    from collections.abc import Callable


_network_unavailable_reason = cast(
    "Callable[[BaseException], str | None]",
    vars(providers_conftest)["_network_unavailable_reason"],
)


def _connect_error_from_gaierror(errno: int, message: str) -> httpx.ConnectError:
    """Reproduce the real chained ConnectError httpx raises on a DNS failure.

    ``httpx`` wraps the low-level :class:`socket.gaierror` from ``getaddrinfo``
    in a :class:`httpx.ConnectError`, linking the original via ``__cause__``
    exactly as the ``raise ... from`` in its transport does.

    Args:
        errno: The socket error number (11001 on Windows, -2/-3 on Linux).
        message: The transport-level error message.

    Returns:
        httpx.ConnectError: A ConnectError whose ``__cause__`` is the gaierror.
    """
    gai = socket.gaierror(errno, "getaddrinfo failed")
    err = httpx.ConnectError(message)
    err.__cause__ = gai
    return err


def test_windows_getaddrinfo_failure_is_classified_as_network_down() -> None:
    """A Windows [Errno 11001] getaddrinfo ConnectError is reported as network-down."""
    exc = _connect_error_from_gaierror(11001, "[Errno 11001] getaddrinfo failed")
    reason = _network_unavailable_reason(exc)
    assert reason is not None, "offline DNS failure must be classified as a missing network"
    assert reason in {"getaddrinfo failed", "[errno 11001]"}


def test_linux_name_resolution_failure_is_classified_as_network_down() -> None:
    """A Linux name-resolution failure surfaced only in the cause chain is detected."""
    root = socket.gaierror(-3, "Temporary failure in name resolution")
    outer = httpx.ConnectError("connection attempt failed")
    outer.__cause__ = root
    reason = _network_unavailable_reason(outer)
    assert reason is not None, "the classifier must walk the __cause__ chain for the signal"
    assert reason in {"temporary failure in name resolution", "[errno -3]"}


def test_connection_refused_to_endpoint_is_network_down() -> None:
    """A refused connection to the live endpoint is treated as an environment gate."""
    exc = httpx.ConnectError("[Errno 111] Connection refused")
    reason = _network_unavailable_reason(exc)
    assert reason == "connection refused"


def test_http_500_against_reachable_host_is_not_network_down() -> None:
    """A server-side 500 against a reachable host is a real failure, not a skip."""
    request = httpx.Request("POST", "https://api.example.com/v1/chat")
    response = httpx.Response(500, request=request, text="internal server error")
    exc = httpx.HTTPStatusError("500 Internal Server Error", request=request, response=response)
    assert _network_unavailable_reason(exc) is None, "a reachable-host 5xx must propagate, not skip"


def test_connection_reset_is_not_classified_as_network_down() -> None:
    """A mid-stream connection reset is a real transport fault, not a missing network.

    ``connection reset`` deliberately is not in the signal set: it indicates the
    host was reachable and then dropped the stream, which can expose a genuine
    product defect and must not be silently skipped.
    """
    exc = httpx.ReadError("[Errno 104] Connection reset by peer")
    assert _network_unavailable_reason(exc) is None


def test_account_limit_message_is_not_network_down() -> None:
    """A billing/quota message is out of scope for the network classifier (returns None)."""
    exc = RuntimeError("insufficient_quota: exceeded your current quota")
    assert _network_unavailable_reason(exc) is None
