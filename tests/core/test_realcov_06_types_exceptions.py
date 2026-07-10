# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for the core exception hierarchy in ``core.types``.

These tests instantiate the genuine exception classes used by config and
sandbox code paths, then assert on the real attributes, the real ``str()``
representation, and the real subclass relationships. The exceptions are pure
data-carrying logic units with no external dependency, so they are constructed
and inspected directly.
"""

from __future__ import annotations

import pytest

from intellicrack.core.types import (
    ConfigurationError,
    IntellicrackError,
    SandboxError,
    SandboxTimeoutError,
)


_ERROR_CODE = 42
_TIMEOUT_SECONDS = 12.5


def test_intellicrack_error_carries_message_code_and_details() -> None:
    """The base error preserves message, code, details and ``str()`` output."""
    details = {"path": "C:/Windows/System32/kernel32.dll"}
    error = IntellicrackError("base failure", error_code=_ERROR_CODE, details=details)
    assert str(error) == "base failure"
    assert error.message == "base failure"
    assert error.error_code == _ERROR_CODE
    assert error.details == details
    assert isinstance(error, Exception)


def test_intellicrack_error_defaults_to_empty_details() -> None:
    """When no details are supplied the base error stores an empty dict."""
    error = IntellicrackError("no details")
    assert error.details == {}
    assert error.error_code is None


def test_configuration_error_exposes_config_fields() -> None:
    """``ConfigurationError`` records config_key, expected_type, actual_value."""
    error = ConfigurationError(
        "invalid port value",
        config_key="tools.ghidra.port",
        expected_type="int",
        actual_value="not-a-port",
        error_code=_ERROR_CODE,
    )
    assert isinstance(error, IntellicrackError)
    assert str(error) == "invalid port value"
    assert error.config_key == "tools.ghidra.port"
    assert error.expected_type == "int"
    assert error.actual_value == "not-a-port"
    assert error.error_code == _ERROR_CODE


def test_sandbox_error_exposes_sandbox_fields() -> None:
    """``SandboxError`` records sandbox_type and vm_state and is catchable as base."""
    error = SandboxError("vm crashed", sandbox_type="docker", vm_state="stopped")
    assert isinstance(error, IntellicrackError)
    assert error.sandbox_type == "docker"
    assert error.vm_state == "stopped"
    with pytest.raises(IntellicrackError, match="vm crashed"):
        raise error


def test_sandbox_timeout_error_is_sandbox_error_subclass() -> None:
    """``SandboxTimeoutError`` extends ``SandboxError`` and adds timeout_seconds."""
    error = SandboxTimeoutError(
        "execution timed out",
        timeout_seconds=_TIMEOUT_SECONDS,
        sandbox_type="docker",
        vm_state="running",
    )
    assert isinstance(error, SandboxError)
    assert isinstance(error, IntellicrackError)
    assert error.timeout_seconds == _TIMEOUT_SECONDS
    assert error.sandbox_type == "docker"
    assert error.vm_state == "running"
