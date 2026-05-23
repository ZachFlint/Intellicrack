# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for F11 silent except blocks in GhidraBridge."""

from __future__ import annotations

from typing import Any, NoReturn
from unittest.mock import patch

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


class _FakeBridgeClient:
    """Fake bridge client to simulate remote errors."""

    def __init__(self) -> None:
        pass

    def remote_exec(self, _code: str) -> NoReturn:
        """Raise an exception to trigger the error handling path.

        Args:
            _code: Remote code.

        Raises:
            RuntimeError: Simulated remote error.
        """
        err_msg = "simulated_remote_error"
        raise RuntimeError(err_msg)

    def remote_eval(self, _expr: str) -> NoReturn:
        """Raise an exception to trigger the error handling path.

        Args:
            _expr: Remote expression.

        Raises:
            RuntimeError: Simulated remote error.
        """
        err_msg = "simulated_remote_error"
        raise RuntimeError(err_msg)


@pytest.fixture
def bridge_with_failing_fake() -> GhidraBridge:
    """Wire a GhidraBridge to a failing fake RPC client.

    Returns:
        GhidraBridge: GhidraBridge wired to a failing fake client.
    """
    bridge = GhidraBridge()
    fake = _FakeBridgeClient()
    bridge.attach_remote_bridge(fake)
    return bridge


@pytest.mark.asyncio
async def test_f11_define_structure_logging(bridge_with_failing_fake: GhidraBridge) -> None:
    """Verify that define_structure logs a warning when execution fails.

    Args:
        bridge_with_failing_fake: Bridge with failing fake.
    """
    fields: list[dict[str, Any]] = [
        {"name": "field1", "type": "int", "size": 4},
    ]
    with patch("intellicrack.bridges.ghidra._logger") as mock_logger:
        with pytest.raises(ToolError, match="Define structure failed"):
            await bridge_with_failing_fake.define_structure("MyStruct", fields)

        mock_logger.warning.assert_called_once()
        args, kwargs = mock_logger.warning.call_args
        assert args[0] == "ghidra_define_structure_failed"
        assert kwargs["struct_name"] == "MyStruct"
        assert "simulated_remote_error" in kwargs["error"]


@pytest.mark.asyncio
async def test_f11_create_function_logging(bridge_with_failing_fake: GhidraBridge) -> None:
    """Verify that create_function logs a warning when execution fails.

    Args:
        bridge_with_failing_fake: Bridge with failing fake.
    """
    with patch("intellicrack.bridges.ghidra._logger") as mock_logger:
        with pytest.raises(ToolError, match="Create function failed"):
            await bridge_with_failing_fake.create_function(0x401000, "func1")

        mock_logger.warning.assert_called_once()
        args, kwargs = mock_logger.warning.call_args
        assert args[0] == "ghidra_create_function_failed"
        assert kwargs["address"] == hex(0x401000)
        assert "simulated_remote_error" in kwargs["error"]
