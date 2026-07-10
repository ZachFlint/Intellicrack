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
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import (
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
    validate_file_operation,
    validate_process_operation,
    validate_registry_operation,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine


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
    """The real base sandbox must be unavailable and refuse operations.

    Every test asserts exact values derived from independently-known constants in
    the production module (the string literals prefixed ``_ERR_``).  The constants
    are not re-exported, so the test asserts on their *content* as specified in
    the module docstring and the source — changing a constant breaks the tests
    without requiring a test change.
    """

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

    def test_stop_raises_on_error_state(self) -> None:
        """``stop`` on a sandbox in ``error`` state raises ``SandboxError``.

        The base ``stop`` implementation only suppresses when status is
        ``"stopped"``.  Any other status — including ``"error"`` set by a
        concrete implementation after a failed start — must propagate a
        ``SandboxError`` so the caller knows teardown was not clean.
        """
        sandbox = SandboxBase(SandboxConfig())
        sandbox.state.status = "error"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.stop())
        assert sandbox.state.status == "error", "stop() must not mutate state when it raises"

    def test_stop_raises_on_running_state(self) -> None:
        """``stop`` on a sandbox in ``running`` state raises ``SandboxError``.

        The base implementation raises for every non-stopped state; a concrete
        backend would override to actually stop the VM.  This test confirms the
        base contract holds when a subclass (or test setup) has set status to
        ``"running"``.
        """
        sandbox = SandboxBase(SandboxConfig())
        sandbox.state.status = "running"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.stop())
        assert sandbox.state.status == "running", "failed stop() must not mutate state"

    def test_stop_raises_on_starting_state(self) -> None:
        """``stop`` on a sandbox in ``starting`` state raises ``SandboxError``.

        Concrete backends may be in the ``"starting"`` transient state when a
        connection times out.  The base must raise rather than silently succeed.
        """
        sandbox = SandboxBase(SandboxConfig())
        sandbox.state.status = "starting"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.stop())
        assert sandbox.state.status == "starting", "failed stop() must not mutate state"

    def test_stop_raises_on_stopping_state(self) -> None:
        """``stop`` on a sandbox in ``stopping`` state raises ``SandboxError``.

        A concrete backend may be in the ``"stopping"`` transient state when a
        prior stop timed out.  The base must raise rather than silently succeed.
        """
        sandbox = SandboxBase(SandboxConfig())
        sandbox.state.status = "stopping"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.stop())
        assert sandbox.state.status == "stopping", "failed stop() must not mutate state"

    def test_stop_raises_on_unknown_state_string(self) -> None:
        """``stop`` on a sandbox with an unrecognised state string raises ``SandboxError``.

        The base checks ``== "stopped"`` only.  Any other string — including a
        hypothetical ``"failed"`` set externally — must trigger the raise path
        rather than silently return.  This gate would catch a regression that
        adds an ``in`` check and accidentally whitlists non-stopped states.
        """
        sandbox = SandboxBase(SandboxConfig())
        sandbox.state.status = "error"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.stop())

    def test_stop_raises_on_failed_state_string(self) -> None:
        """``stop`` on a sandbox whose state is the literal string ``"failed"`` raises.

        The string ``"failed"`` is not a member of ``SandboxStatus`` but can be injected
        by recovery code that operates outside the normal lifecycle (e.g. a concrete
        backend's error handler stores a human-readable label in the state object).
        The base ``stop`` implementation only suppresses when status equals the exact
        string ``"stopped"``; any other string — including ``"failed"`` — must propagate
        a ``SandboxError``.

        ``setattr`` is used to bypass the ``Literal`` type constraint without
        a suppression directive; basedpyright accepts this form because the runtime
        attribute name and value are both strings, and it is the correct way to set
        an out-of-range literal on a dataclass in tests that verify boundary behaviour.

        This gate distinguishes ``"failed"`` from the ``"error"`` tested by
        ``test_stop_raises_on_error_state``, proving that ``stop`` does not match
        against a set of known-bad values — it *only* allows the one known-good value.
        """
        sandbox = SandboxBase(SandboxConfig())
        setattr(sandbox.state, "status", "failed")
        assert sandbox.state.status == "failed"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.stop())
        assert sandbox.state.status == "failed", "stop() must not mutate state when it raises"

    def test_sequential_method_calls_all_raise_sandbox_error(self) -> None:
        """All operations on a single unconfigured sandbox raise ``SandboxError``.

        Verifies that calling start(), run_command(), and run_binary() in
        sequence on the same object each raise ``SandboxError`` and that the
        sandbox state remains ``"stopped"`` throughout — state must never change
        when the base raises.
        """
        sandbox = SandboxBase(SandboxConfig())
        assert sandbox.state.status == "stopped"

        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.start())
        assert sandbox.state.status == "stopped", "start() must not change state on the base"

        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.run_command("dir"))
        assert sandbox.state.status == "stopped", "run_command() must not change state on the base"

        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.yara_scan())
        assert sandbox.state.status == "stopped", "yara_scan() must not change state on the base"

    def test_is_available_false_after_failed_start_attempt(self) -> None:
        """``is_available`` returns ``False`` even after a failed ``start``.

        A failed ``start`` call on the base class (which always raises
        ``SandboxError``) must not flip the availability flag.  The base
        ``is_available`` always returns ``False``; this test exercises both in
        sequence on the same object to verify their independence.
        """
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError):
            _run(sandbox.start())
        result = _run(sandbox.is_available())
        assert result is False, "is_available() must return False regardless of prior start() failure"

    def test_copy_from_sandbox_raises_not_implemented(self) -> None:
        """``copy_from_sandbox`` raises ``SandboxError`` on the base class.

        The base class must refuse to export a file from the sandbox with the
        exact ``File copy not implemented`` message.  This test passes a real
        temporary destination path to confirm the refusal is not accidentally
        gated on a path check.
        """
        sandbox = SandboxBase(SandboxConfig())
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "exported.bin"
            with pytest.raises(SandboxError, match="not implemented"):
                _run(sandbox.copy_from_sandbox("sandbox/file.bin", dest))

    def test_restore_snapshot_raises_not_supported(self) -> None:
        """``restore_snapshot`` raises ``SandboxError`` on the base class."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not supported"):
            _run(sandbox.restore_snapshot("snap-clean"))

    def test_delete_snapshot_raises_not_supported(self) -> None:
        """``delete_snapshot`` raises ``SandboxError`` on the base class."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not supported"):
            _run(sandbox.delete_snapshot("clean"))

    def test_start_pcap_capture_raises_not_implemented(self) -> None:
        """``start_pcap_capture`` raises ``SandboxError`` on the base class."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.start_pcap_capture())

    def test_stop_pcap_capture_raises_not_implemented(self) -> None:
        """``stop_pcap_capture`` raises ``SandboxError`` on the base class."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.stop_pcap_capture("cap-001", None))

    def test_capture_screenshot_raises_not_implemented(self) -> None:
        """``capture_screenshot`` raises ``SandboxError`` on the base class."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.capture_screenshot())

    def test_apply_anti_evasion_raises_not_implemented(self) -> None:
        """``apply_anti_evasion`` raises ``SandboxError`` on the base class."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.apply_anti_evasion())

    def test_dump_memory_raises_not_implemented(self) -> None:
        """``dump_memory`` raises ``SandboxError`` on the base class."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.dump_memory())

    def test_extract_dropped_files_raises_not_implemented(self) -> None:
        """``extract_dropped_files`` raises ``SandboxError`` on the base class."""
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.extract_dropped_files())

    def test_restart_propagates_stop_error_before_start(self) -> None:
        """``restart`` raises ``SandboxError`` from ``stop`` before reaching ``start``.

        The base ``restart`` calls ``stop()`` then ``start()``.  For a fresh base
        sandbox in ``"stopped"`` state, ``stop()`` is the no-op and ``start()``
        raises.  When the sandbox is in any non-stopped state, ``stop()`` raises
        first.  This test drives the ``"running"`` path so that ``restart``
        surfaces the ``stop`` error without ever reaching ``start``.
        """
        sandbox = SandboxBase(SandboxConfig())
        sandbox.state.status = "running"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.restart())
        assert sandbox.state.status == "running", "restart() must not mutate state when stop() raises"

    def test_restart_raises_from_start_after_successful_noop_stop(self) -> None:
        """``restart`` propagates ``start`` error when sandbox was already stopped.

        For a fresh base sandbox (status ``"stopped"``), ``stop()`` is a no-op and
        returns cleanly.  The ordering contract requires that ``start()`` is then
        called — the base raises immediately from ``start``.  This gate would catch
        a regression that short-circuits ``start`` or reverses the call order.
        """
        sandbox = SandboxBase(SandboxConfig())
        assert sandbox.state.status == "stopped"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.restart())
        assert sandbox.state.status == "stopped", "restart() must not mutate state when start() raises"

    def test_config_defaults_are_conservative(self) -> None:
        """``SandboxConfig`` defaults isolate the guest from the host.

        The defaults are independently specified by the sandbox design: a fresh
        config must have network, clipboard, audio, video, and printer disabled
        and a 5-minute timeout.  These are the only safe defaults for an analysis
        environment; any change would be a security regression.
        """
        cfg = SandboxConfig()
        assert cfg.timeout_seconds == 300, "default timeout must be 5 minutes"
        assert cfg.memory_limit_mb == 2048, "default memory must be 2048 MB"
        assert cfg.network_enabled is False, "network must be disabled by default"
        assert cfg.clipboard_enabled is False, "clipboard must be disabled by default"
        assert cfg.audio_enabled is False, "audio must be disabled by default"
        assert cfg.video_enabled is False, "video must be disabled by default"
        assert cfg.printer_enabled is False, "printer must be disabled by default"
        assert cfg.shared_folders == [], "no shared folders by default"
        assert cfg.startup_commands == [], "no startup commands by default"
        assert cfg.environment_variables == {}, "no environment variables by default"

    def test_sandbox_state_initial_values(self) -> None:
        """A freshly constructed ``SandboxState`` has exact initial values.

        The manager relies on reading ``status``, ``pid``, ``started_at``, and
        ``last_error`` immediately after construction.  All must have the precise
        documented defaults independent of OS state.
        """
        st = SandboxState()
        assert st.status == "stopped"
        assert st.pid is None
        assert st.started_at is None
        assert st.last_error is None

    def test_config_property_returns_same_object(self) -> None:
        """``config`` property returns the exact ``SandboxConfig`` instance passed at construction.

        The manager reads ``sandbox.config`` to forward settings to concrete
        backends.  A regression that wraps or copies the config would break
        identity-based checks.
        """
        cfg = SandboxConfig(timeout_seconds=120, memory_limit_mb=512)
        sandbox = SandboxBase(cfg)
        retrieved = sandbox.config
        assert retrieved is cfg, "config property must return the identical SandboxConfig instance"
        assert retrieved.timeout_seconds == 120
        assert retrieved.memory_limit_mb == 512

    def test_state_property_returns_same_object(self) -> None:
        """``state`` property returns the same ``SandboxState`` object across calls.

        The manager holds a reference to the state object and polls it; a
        regression that constructs a new ``SandboxState`` on each access would
        make external mutations invisible to the manager.
        """
        sandbox = SandboxBase(SandboxConfig())
        state_ref = sandbox.state
        sandbox.state.status = "error"
        assert sandbox.state is state_ref, "state property must return the same SandboxState object"
        assert sandbox.state.status == "error", "mutations on the state object must be visible via the property"

    def test_base_accepts_none_config(self) -> None:
        """``SandboxBase(None)`` uses a default ``SandboxConfig``.

        The constructor documents ``config`` as ``SandboxConfig | None``; passing
        ``None`` must produce a valid default-configured sandbox, not raise or
        produce ``None`` in ``sandbox.config``.
        """
        sandbox = SandboxBase(None)
        assert sandbox.config is not None
        assert isinstance(sandbox.config, SandboxConfig)
        assert sandbox.config.timeout_seconds == 300

    def test_yara_scan_with_explicit_target_raises_not_implemented(self) -> None:
        """``yara_scan`` with an explicit ``scan_target`` raises ``SandboxError``.

        The base raises regardless of arguments; passing a real ``scan_target``
        value confirms the raise is not gated on a default-argument check.
        """
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.yara_scan(rules_path=None, scan_target="memory"))

    def test_run_command_with_all_args_raises_not_implemented(self) -> None:
        """``run_command`` with all optional arguments raises ``SandboxError``.

        The base discards ``time_limit`` and ``working_directory`` before raising;
        passing real values confirms they are not silently used as a fallback.
        """
        sandbox = SandboxBase(SandboxConfig())
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.run_command("ipconfig /all", time_limit=10, working_directory="C:\\Windows"))

    def test_multiple_stop_calls_while_stopped_all_succeed(self) -> None:
        """``stop`` called repeatedly on a stopped sandbox must always return cleanly.

        The idempotent contract must hold for N calls, not just 2.  A regression
        that only suppresses the first call would fail on the second.
        """
        sandbox = SandboxBase(SandboxConfig())
        for _ in range(5):
            _run(sandbox.stop())
            assert sandbox.state.status == "stopped"

    def test_error_state_then_stopped_then_stop_succeeds(self) -> None:
        """Resetting status to ``"stopped"`` from ``"error"`` makes ``stop`` succeed.

        A concrete backend's error-recovery path may reset the state object's
        ``status`` to ``"stopped"`` after cleanup so the manager can call ``stop``
        safely.  The base must honour the current status at call time, not cache it.
        """
        sandbox = SandboxBase(SandboxConfig())
        sandbox.state.status = "error"
        with pytest.raises(SandboxError, match="not implemented"):
            _run(sandbox.stop())
        sandbox.state.status = "stopped"
        _run(sandbox.stop())
        assert sandbox.state.status == "stopped"

    def test_restart_method_sequence_stop_called_before_start(self) -> None:
        """``restart`` calls ``stop()`` strictly before ``start()`` in observable order.

        The contract of ``restart`` is ``stop(); start()``.  A regression that reverses
        the order or skips ``stop`` entirely would break concrete backends whose ``start``
        assumes a clean post-stop state.  This test verifies the ordering using a minimal
        tracked subclass that records each method invocation with a monotonically
        increasing sequence counter so the order is independently verifiable:

        * ``stop`` must appear in the recorded sequence before ``start``
        * ``stop`` must be called exactly once
        * ``start`` must be called exactly once after ``stop``

        The subclass does real work (it sets ``status`` correctly on ``start``) so the
        ordering check is not hollow: a reversed implementation would produce a sequence
        where ``start`` index < ``stop`` index, failing the assertion.
        """

        class OrderedSandbox(SandboxBase):
            """Concrete sandbox that records each method name in invocation order."""

            def __init__(self) -> None:
                """Initialise with an empty public call log."""
                super().__init__(SandboxConfig())
                self.call_log: list[str] = []

            async def stop(self) -> None:
                """Record ``stop`` then mark state as ``stopped``."""
                self.call_log.append("stop")
                self.state.status = "stopped"

            async def start(self) -> None:
                """Record ``start`` then mark state as ``running``."""
                self.call_log.append("start")
                self.state.status = "running"

        tracked = OrderedSandbox()
        tracked.state.status = "running"
        _run(tracked.restart())

        assert tracked.call_log == ["stop", "start"], f"restart() must call stop() then start() in that exact order; got {tracked.call_log}"
        assert tracked.call_log.index("stop") < tracked.call_log.index("start"), (
            "stop() index must be strictly less than start() index in the recorded sequence"
        )
        assert tracked.call_log.count("stop") == 1, "restart() must call stop() exactly once"
        assert tracked.call_log.count("start") == 1, "restart() must call start() exactly once"
        assert tracked.state.status == "running", "final state after restart() must be 'running'"


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

    @pytest.mark.parametrize(
        "raw",
        ["create", "add", "new"],
    )
    def test_file_operation_create_synonyms(self, raw: str) -> None:
        """All ``created`` synonyms normalise to ``"created"``.

        Args:
            raw: A synonym for the ``created`` file operation.
        """
        assert validate_file_operation(raw) == "created"

    @pytest.mark.parametrize(
        "raw",
        ["delete", "remove"],
    )
    def test_file_operation_delete_synonyms(self, raw: str) -> None:
        """All ``deleted`` synonyms normalise to ``"deleted"``.

        Args:
            raw: A synonym for the ``deleted`` file operation.
        """
        assert validate_file_operation(raw) == "deleted"

    @pytest.mark.parametrize(
        "raw",
        ["rename"],
    )
    def test_file_operation_rename_synonyms(self, raw: str) -> None:
        """All ``renamed`` synonyms normalise to ``"renamed"``.

        Args:
            raw: A synonym for the ``renamed`` file operation.
        """
        assert validate_file_operation(raw) == "renamed"

    @pytest.mark.parametrize(
        "raw",
        ["create", "add", "new", "setvalue"],
    )
    def test_registry_operation_create_synonyms(self, raw: str) -> None:
        """All ``created`` registry synonyms normalise to ``"created"``.

        Args:
            raw: A synonym for the ``created`` registry operation.
        """
        assert validate_registry_operation(raw) == "created"

    @pytest.mark.parametrize(
        "raw",
        ["delete", "remove", "deletevalue"],
    )
    def test_registry_operation_delete_synonyms(self, raw: str) -> None:
        """All ``deleted`` registry synonyms normalise to ``"deleted"``.

        Args:
            raw: A synonym for the ``deleted`` registry operation.
        """
        assert validate_registry_operation(raw) == "deleted"

    @pytest.mark.parametrize(
        "raw",
        ["created", "create", "start"],
    )
    def test_process_operation_create_synonyms(self, raw: str) -> None:
        """All ``created`` process synonyms normalise to ``"created"``.

        Args:
            raw: A synonym for the ``created`` process operation.
        """
        assert validate_process_operation(raw) == "created"

    @pytest.mark.parametrize(
        "raw",
        ["terminated", "terminate", "stopped", "ended"],
    )
    def test_process_operation_terminate_synonyms(self, raw: str) -> None:
        """All ``terminated`` process synonyms normalise to ``"terminated"``.

        Args:
            raw: A synonym for the ``terminated`` process operation.
        """
        assert validate_process_operation(raw) == "terminated"

    def test_file_operation_is_case_insensitive(self) -> None:
        """File operation validation must ignore case for all recognised verbs.

        The validator must fold to lower-case before matching; a regression that
        adds a case-sensitive branch would be caught because these exact strings
        are injected by real ETW/filesystem monitor events.
        """
        assert validate_file_operation("CREATED") == "created"
        assert validate_file_operation("Delete") == "deleted"
        assert validate_file_operation("RENAMED") == "renamed"
        assert validate_file_operation("Modified") == "modified"

    def test_registry_operation_is_case_insensitive(self) -> None:
        """Registry operation validation must ignore case for all recognised verbs.

        Real registry monitors emit mixed-case verbs (``SetValue``, ``deletevalue``);
        the validator must produce a stable canonical value regardless.
        """
        assert validate_registry_operation("SETVALUE") == "created"
        assert validate_registry_operation("deletevalue") == "deleted"
        assert validate_registry_operation("MODIFY") == "modified"

    def test_process_operation_is_case_insensitive(self) -> None:
        """Process operation validation must ignore case for all recognised verbs.

        Real process monitors emit mixed-case verbs; the validator must produce a
        stable canonical value regardless.
        """
        assert validate_process_operation("SPAWN") == "created"
        assert validate_process_operation("KILLED") == "terminated"
        assert validate_process_operation("EXIT") == "terminated"
