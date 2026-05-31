# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for ``intellicrack.sandbox.base`` (FIX UNIT 12a).

The audit flags the base sandbox methods as ``abstract``/``stubbed`` and never
exercised on a real object. The base class is not abstract — it is a concrete
class whose default methods implement a real, observable contract: an
unconfigured backend is unavailable and refuses operations with a precise
:class:`SandboxError`, while ``stop`` on an already-stopped sandbox is a real
idempotent no-op. These tests instantiate the REAL :class:`SandboxBase` and
assert that genuine contract, plus drive the operation-validation functions over
the REAL operation vocabulary every concrete sandbox feeds them.

No backend is mocked: the behaviour under test IS the base class's own real
implementation. Concrete-backend execution is covered separately by the QEMU
real-operation tests.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import (
    SandboxBase,
    SandboxConfig,
    SandboxError,
    validate_file_operation,
    validate_process_operation,
    validate_registry_operation,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Execute ``coro`` on a dedicated event loop for test isolation.

    Args:
        coro: Awaitable to run to completion.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestBaseUnconfiguredContract:
    """The real base sandbox must be unavailable and refuse operations."""

    def test_base_reports_unavailable(self) -> None:
        """A bare ``SandboxBase`` truthfully reports that it cannot be used."""
        sandbox = SandboxBase(SandboxConfig())
        assert _run(sandbox.is_available()) is False, "an unconfigured base sandbox must report unavailable"
        assert sandbox.vnc_port is None, "the base sandbox exposes no VNC port"
        assert sandbox.state.status == "stopped", "a fresh base sandbox starts stopped"

    def test_start_raises_not_implemented(self) -> None:
        """``start`` on the base class raises a precise ``SandboxError``."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.start())

    def test_run_command_refuses_real_command(self) -> None:
        """``run_command`` refuses a real command string with ``SandboxError``."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.run_command("whoami /all"))

    def test_run_binary_refuses_real_binary(self, real_pe_exe: Path) -> None:
        """``run_binary`` refuses a real PE executable with ``SandboxError``.

        Args:
            real_pe_exe: Real System32 PE executable fixture.
        """
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.run_binary(real_pe_exe))

    def test_copy_to_sandbox_refuses_real_file(self, real_pe_dll: Path) -> None:
        """``copy_to_sandbox`` refuses to copy a real DLL with ``SandboxError``.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.copy_to_sandbox(real_pe_dll, "input/kernel32.dll"))

    def test_snapshot_operations_report_unsupported(self) -> None:
        """Snapshot operations report a precise ``not supported`` error."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not supported"):
            _run(sandbox.take_snapshot("clean"))
        with pytest.raises(SandboxError, match="not supported"):
            _run(sandbox.list_snapshots())

    def test_yara_scan_reports_not_implemented(self) -> None:
        """``yara_scan`` on the base class reports ``not implemented``."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.yara_scan())

    def test_stop_is_idempotent_no_op_when_stopped(self) -> None:
        """``stop`` on an already-stopped base sandbox is a real no-op.

        The default ``stop`` raises for a non-stopped base sandbox but returns
        cleanly when the state is already ``stopped`` — the genuine idempotent
        teardown contract the manager relies on.
        """
        sandbox = SandboxBase(SandboxConfig())
        assert sandbox.state.status == "stopped"
        _run(sandbox.stop())
        assert sandbox.state.status == "stopped", "idempotent stop must leave the state stopped"


class TestOperationValidationRealVocabulary:
    """Validators must normalise the REAL operation strings backends emit."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Created", "created"),
            ("modify", "modified"),
            ("WRITE", "modified"),
            ("unlink", "deleted"),
            ("move", "renamed"),
            ("unexpected", "modified"),
        ],
    )
    def test_file_operation_normalisation(self, raw: str, expected: str) -> None:
        """File-monitor verbs normalise to the canonical ``FileOperation``.

        Args:
            raw: Raw verb a real file monitor could emit.
            expected: Canonical normalised value.
        """
        assert validate_file_operation(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("SetValue", "created"),
            ("update", "modified"),
            ("DeleteValue", "deleted"),
            ("garbage", "modified"),
        ],
    )
    def test_registry_operation_normalisation(self, raw: str, expected: str) -> None:
        """Registry-monitor verbs normalise to the canonical ``RegistryOperation``.

        Args:
            raw: Raw verb a real registry monitor could emit.
            expected: Canonical normalised value.
        """
        assert validate_registry_operation(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("spawn", "created"),
            ("launched", "created"),
            ("killed", "terminated"),
            ("exit", "terminated"),
            ("anything", "created"),
        ],
    )
    def test_process_operation_normalisation(self, raw: str, expected: str) -> None:
        """Process-monitor verbs normalise to the canonical ``ProcessOperation``.

        Args:
            raw: Raw verb a real process monitor could emit.
            expected: Canonical normalised value.
        """
        assert validate_process_operation(raw) == expected
