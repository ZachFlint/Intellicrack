# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the Cutter/rizin bridge JSON extraction and timeout.

These tests exercise the real ``_extract_rizin_json`` helper (not a mock)
that both ``_cmd_json`` and ``get_libraries`` rely on to recover JSON payloads
from rizin's ``j``-suffixed commands, which can emit non-JSON prefix/suffix
bytes over the pipe. They also pin the command timeout so a regression back to
the original 60-second value is caught.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, cast

import pytest

from intellicrack.bridges import cutter
from intellicrack.core.types import ToolError


# Private module symbols accessed via getattr + cast to avoid reportPrivateUsage,
# matching the established pattern in test_installer_ops_wave5.py.
_extract_rizin_json: Callable[[str, str], object] = cast(
    Callable[[str, str], object],
    getattr(cutter, "_extract_rizin_json"),
)
_find_json_start: Callable[[str], int | None] = cast(
    Callable[[str], int | None],
    getattr(cutter, "_find_json_start"),
)
_balanced_json_slice: Callable[[str, int], str | None] = cast(
    Callable[[str, int], str | None],
    getattr(cutter, "_balanced_json_slice"),
)


def _command_timeout() -> float:
    """Return the bridge command timeout without tripping reportPrivateUsage.

    Returns:
        float: The bridge's ``_R2_COMMAND_TIMEOUT`` module constant.
    """
    return cast("float", getattr(cutter, "_R2_COMMAND_TIMEOUT"))


def test_extractor_recovers_object_after_leading_junk_bytes() -> None:
    """Leading non-JSON bytes before an object are stripped before parsing."""
    payload: dict[str, Any] = {"name": "kernel32.dll", "vaddr": 4096}
    raw = "\x00\x01\x02" + json.dumps(payload)

    parsed = _extract_rizin_json(raw, "ilj")

    assert parsed == payload


def test_extractor_recovers_array_from_extra_data_prefix() -> None:
    """A value-like junk prefix that triggers ``Extra data`` is recovered.

    Raw output of the form ``"12[...]"`` makes a naive ``json.loads`` decode
    the leading ``12`` and then fail with ``Extra data``. The extractor must
    slice the real array container instead.
    """
    payload: list[dict[str, Any]] = [{"vaddr": 4096, "paddr": 1024, "name": ".text"}]
    raw = "12" + json.dumps(payload)

    with pytest.raises(json.JSONDecodeError):
        json.loads(raw)

    parsed = _extract_rizin_json(raw, "iSj")

    assert parsed == payload


def test_extractor_ignores_trailing_junk_after_object() -> None:
    """Trailing pipe noise after a complete object is discarded."""
    payload: dict[str, Any] = {"a": 1, "b": [2, 3]}
    raw = json.dumps(payload) + "\x00trailing-noise"

    parsed = _extract_rizin_json(raw, "ihj")

    assert parsed == payload


def test_extractor_handles_nested_and_string_braces() -> None:
    """Brace balancing respects braces embedded inside string literals."""
    payload: dict[str, Any] = {"comment": "value with } and { braces", "inner": {"k": "]["}}
    raw = "xx" + json.dumps(payload)

    parsed = _extract_rizin_json(raw, "CCj")

    assert parsed == payload


def test_extractor_raises_tool_error_on_output_without_container() -> None:
    """Output containing no JSON container surfaces a clear ToolError."""
    with pytest.raises(ToolError, match="failed to parse rizin JSON output"):
        _extract_rizin_json("not json at all", "iSj")


def test_extractor_raises_tool_error_on_truncated_container() -> None:
    """An unbalanced/truncated container cannot be sliced and raises ToolError."""
    with pytest.raises(ToolError, match="failed to parse rizin JSON output"):
        _extract_rizin_json('junk{"a": 1, "b":', "iSj")


def test_extractor_raises_tool_error_on_balanced_but_invalid_json() -> None:
    """A balanced-but-syntactically-invalid slice raises ToolError, not silence."""
    with pytest.raises(ToolError, match="failed to parse rizin JSON output"):
        _extract_rizin_json("xxx{not: valid, json}", "iSj")


def test_find_json_start_locates_first_container() -> None:
    """The container-start scanner returns the first ``{``/``[`` index."""
    assert _find_json_start("abc[1]") == 3
    assert _find_json_start("no container here") is None


def test_balanced_slice_returns_none_when_unclosed() -> None:
    """The balanced slicer reports ``None`` for a container that never closes."""
    assert _balanced_json_slice('{"a": 1', 0) is None


def test_command_timeout_is_bounded_to_five_seconds() -> None:
    """The command timeout must stay small so a hung pipe fails fast."""
    timeout = _command_timeout()
    assert timeout <= 5.0
    assert cutter.R2_COMMAND_TIMEOUT <= 5.0
    assert timeout > 0.0
