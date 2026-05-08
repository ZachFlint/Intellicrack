# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit3 U10 regression tests for ``intellicrack.core.disassembler``.

Covers:

- F-0002: ``HexDisassembler.auto_detect_arch`` must raise
  :class:`UnsupportedArchitectureError` instead of silently falling back
  to ``("x86_64", ...)`` when the canonical architecture string returned
  by the format detector has no capstone mapping.
- F-0009: ``HexDisassembler.disassemble_to_lines`` must omit the
  ``binary_path`` log field when called with an in-memory buffer (no
  on-disk path) -- the previous implementation logged the literal string
  ``"<bytes-buffer>"`` which polluted log analytics with a synthetic
  filename.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
import structlog.testing

from intellicrack.core.disassembler import (
    HexDisassembler,
    UnsupportedArchitectureError,
    get_disassembler,
)


if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# F-0002: auto_detect_arch must raise on unsupported architectures
# ---------------------------------------------------------------------------


def test_f0002_auto_detect_arch_unknown_raises_unsupported() -> None:
    """An unrecognised arch from the format detector must surface as an error.

    The fix replaces the previous ``dict.get(arch, ("x86_64", ...))``
    silent-fallback with a strict lookup that raises
    :class:`UnsupportedArchitectureError`. The error must carry the
    offending architecture string on the ``arch`` attribute so callers
    can route it to diagnostic surfaces.
    """
    fake_detection: tuple[str, str, bool] = ("ELF", "totally-not-a-real-arch", True)
    with (
        patch(
            "intellicrack.core.disassembler.detect_format_and_arch",
            return_value=fake_detection,
        ),
        pytest.raises(UnsupportedArchitectureError) as exc_info,
    ):
        HexDisassembler.auto_detect_arch(b"\x7fELF\x00\x00\x00\x00\x00\x00\x00\x00")
    assert exc_info.value.arch == "totally-not-a-real-arch"
    assert "totally-not-a-real-arch" in str(exc_info.value)


def test_f0002_auto_detect_arch_unknown_logs_warning() -> None:
    """The unsupported-arch path must emit a structured warning event."""
    fake_detection: tuple[str, str, bool] = ("PE", "exotic-isa", False)
    with (
        patch(
            "intellicrack.core.disassembler.detect_format_and_arch",
            return_value=fake_detection,
        ),
        structlog.testing.capture_logs() as captured,
        pytest.raises(UnsupportedArchitectureError),
    ):
        HexDisassembler.auto_detect_arch(b"MZ\x00\x00")
    warnings = [entry for entry in captured if entry.get("event") == "arch_detection_unsupported"]
    assert warnings, f"expected arch_detection_unsupported warning, got: {captured}"
    assert warnings[0].get("arch") == "exotic-isa"
    assert warnings[0].get("fmt") == "PE"
    assert warnings[0].get("is_64bit") is False
    assert warnings[0].get("log_level") == "warning"


def test_f0002_auto_detect_arch_known_returns_capstone_pair() -> None:
    """Known canonical archs must still resolve to ``(arch, mode)`` pairs."""
    fake_detection: tuple[str, str, bool] = ("ELF", "x86_64", True)
    with patch(
        "intellicrack.core.disassembler.detect_format_and_arch",
        return_value=fake_detection,
    ):
        result = HexDisassembler.auto_detect_arch(b"\x7fELF" + b"\x00" * 16)
    assert result == ("x86", "64")


def test_f0002_auto_detect_arch_no_silent_x86_64_fallback() -> None:
    """The fallback must NOT produce ``("x86", "64")`` for unknown archs.

    Regression guard: the pre-fix code unconditionally returned
    ``("x86_64", "64")`` for any unrecognised architecture, which was
    then mapped to ``("x86", "64")`` downstream. This test asserts the
    new strict behaviour: an exception is raised before any fallback
    pair is produced.
    """
    fake_detection: tuple[str, str, bool] = ("ELF", "garbage-arch-name", True)
    with (
        patch(
            "intellicrack.core.disassembler.detect_format_and_arch",
            return_value=fake_detection,
        ),
        pytest.raises(UnsupportedArchitectureError),
    ):
        HexDisassembler.auto_detect_arch(b"\x7fELF" + b"\x00" * 16)


def test_f0002_unsupported_architecture_error_is_value_error_subclass() -> None:
    """The error must remain a ``ValueError`` subclass for compatibility."""
    err = UnsupportedArchitectureError("some-arch")
    assert isinstance(err, ValueError)
    assert err.arch == "some-arch"


# ---------------------------------------------------------------------------
# F-0009: disassemble_to_lines must not log a placeholder path for buffers
# ---------------------------------------------------------------------------


@pytest.fixture
def disasm() -> HexDisassembler:
    """Return a real :class:`HexDisassembler` instance.

    Skips when capstone is unavailable in the running environment.

    Returns:
        HexDisassembler: A live disassembler.
    """
    instance = get_disassembler()
    if not instance.available:
        pytest.skip("capstone is not available in this environment")
    return instance


def test_f0009_disassemble_to_lines_buffer_omits_binary_path(disasm: HexDisassembler) -> None:
    """Buffer-only calls must not include ``binary_path`` in the log entry.

    Args:
        disasm: Live :class:`HexDisassembler` from the fixture.

    The pre-fix implementation logged ``binary_path="<bytes-buffer>"`` for
    raw-buffer disassembly. The fix conditionally builds the log payload
    so the field is dropped entirely when ``binary_path`` is ``None``.
    """
    buffer = b"\x90\x90\x90\xc3"
    with structlog.testing.capture_logs() as captured:
        disasm.disassemble_to_lines(buffer, base_addr=0, arch="x86", mode="64", count=4)
    invocations = [entry for entry in captured if entry.get("event") == "disassemble_to_lines_invoked"]
    assert invocations, f"expected disassemble_to_lines_invoked event, got: {captured}"
    entry = invocations[0]
    assert "binary_path" not in entry, f"binary_path must be absent for buffer input, got: {entry}"


def test_f0009_disassemble_to_lines_buffer_does_not_log_bytes_placeholder(
    disasm: HexDisassembler,
) -> None:
    """The literal string ``<bytes-buffer>`` must never appear in any log field.

    Args:
        disasm: Live :class:`HexDisassembler` from the fixture.

    Regression guard: the previous code formatted ``binary_path`` using a
    placeholder string that aliased real on-disk paths in log analytics.
    """
    buffer = b"\x48\x31\xc0\xc3"
    with structlog.testing.capture_logs() as captured:
        disasm.disassemble_to_lines(buffer, base_addr=0, arch="x86", mode="64", count=4)
    for entry in captured:
        for value in entry.values():
            assert value != "<bytes-buffer>", f"placeholder string leaked into log entry: {entry}"


def test_f0009_disassemble_to_lines_with_path_includes_binary_path(
    disasm: HexDisassembler,
    tmp_path: Path,
) -> None:
    """When a path IS provided, ``binary_path`` must be included verbatim.

    Args:
        disasm: Live :class:`HexDisassembler` from the fixture.
        tmp_path: Pytest-supplied temporary directory.
    """
    backing = tmp_path / "sample.bin"
    backing.write_bytes(b"\x90\x90\xc3")
    with structlog.testing.capture_logs() as captured:
        disasm.disassemble_to_lines(
            b"\x90\x90\xc3",
            base_addr=0,
            arch="x86",
            mode="64",
            count=3,
            binary_path=backing,
        )
    invocations = [entry for entry in captured if entry.get("event") == "disassemble_to_lines_invoked"]
    assert invocations, f"expected log event, got: {captured}"
    assert invocations[0].get("binary_path") == str(backing)
