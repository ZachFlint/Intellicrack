# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for ``SandboxManager._build_sandbox``'s config resolution.

The effective configuration must merge the per-call ``SandboxConfig`` onto the
manager's stored ``_default_config`` rather than resolve as
``config or self._default_config``. Every real caller
(``SandboxBridge.create``/``.restart``) always builds and passes a fully
populated ``SandboxConfig``, and a dataclass instance is always truthy, so
that fallback would never be reached: the stored ``_default_config`` -- which
carries the application-level "Configure Sandbox" dialog overrides such as
``block_telemetry`` and ``shared_folders`` -- would be silently discarded on
every call.

These tests exercise the real, unmodified ``_build_sandbox``/``_resolve_config``
merge logic (via a thin subclass that exposes it publicly, so external test
code never touches a private attribute directly) and assert on the real
``SandboxConfig`` the constructed backend was actually given.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.manager import SandboxManager


if TYPE_CHECKING:
    from intellicrack.sandbox.manager import SandboxType


class _ConfigMergeManager(SandboxManager):
    """``SandboxManager`` subclass exposing the private config merge for direct testing.

    ``_build_sandbox`` and ``_resolve_config`` are private because they are
    implementation details of the manager, not because external test code
    should be unable to exercise them: this subclass forwards to the real,
    unmodified private methods from inside its own method body (legitimate
    protected access within the class hierarchy) and exposes only a plain
    public method, so calling code outside ``intellicrack.sandbox.manager``
    never performs the private attribute access itself.
    """

    def resolve_effective_config(
        self,
        sandbox_type: SandboxType,
        config: SandboxConfig | None,
    ) -> SandboxConfig:
        """Build a backend for ``sandbox_type``/``config`` and return its effective config.

        ``_build_sandbox`` is synchronous and performs no I/O (it only picks a
        backend class and constructs it), so this is safe and deterministic to
        call directly in a unit test.

        Args:
            sandbox_type: Sandbox backend type to construct.
            config: Per-call configuration override, or ``None`` to use the
                stored defaults unchanged.

        Returns:
            SandboxConfig: The configuration the constructed backend actually
            received, i.e. the real result of the manager's config merge.
        """
        sandbox = self._build_sandbox(sandbox_type, config)
        return sandbox.config


class TestOperatorDefaultsSurviveAPopulatedPerCallConfig:
    """Fields a call leaves unspecified come from ``_default_config``."""

    def test_operator_block_telemetry_and_shared_folder_overrides_take_effect(self) -> None:
        """block_telemetry and shared_folders configured app-wide reach the constructed sandbox.

        ``per_call`` mirrors exactly what ``SandboxBridge.create()`` builds
        when a caller supplies ``timeout_seconds``/``network_enabled``/
        ``memory_limit_mb`` but never touches ``block_telemetry`` or
        ``shared_folders`` (``SandboxBridge.create``/``.restart`` accept no
        ``shared_folders`` parameter at all, and leave ``block_telemetry`` at
        their own default of ``True`` when the caller does not pass it) - so
        both fields sit at ``SandboxConfig``'s class-level defaults on the
        object the manager actually receives, exactly as they would from the
        real bridge.
        """
        operator_shared_folders = [(Path("C:/shared"), "S", True)]
        stored_defaults = SandboxConfig(
            block_telemetry=False,
            shared_folders=operator_shared_folders,
        )
        manager = _ConfigMergeManager(default_config=stored_defaults)

        per_call = SandboxConfig(timeout_seconds=999, network_enabled=True, memory_limit_mb=8192)

        effective = manager.resolve_effective_config("windows", per_call)

        assert effective.timeout_seconds == 999, "an explicitly-overridden field must win"
        assert effective.network_enabled is True, "an explicitly-overridden field must win"
        assert effective.memory_limit_mb == 8192, "an explicitly-overridden field must win"
        assert effective.block_telemetry is False, (
            "block_telemetry was left at SandboxConfig's class default by the caller; "
            "the manager's stored (operator-configured) default must fill it in"
        )
        assert effective.shared_folders == operator_shared_folders, (
            "shared_folders is never exposed by SandboxBridge.create/restart at all; "
            "the manager's stored (operator-configured) default must always supply it"
        )


class TestMergeCorrectnessProperties:
    """Guards two specific implementation choices in the field-by-field merge."""

    def test_explicit_falsy_override_is_not_mistaken_for_unspecified(self) -> None:
        """An explicit block_telemetry=False always wins, even against a stored True default."""
        stored_defaults = SandboxConfig(block_telemetry=True)
        manager = _ConfigMergeManager(default_config=stored_defaults)

        per_call = SandboxConfig(block_telemetry=False)

        effective = manager.resolve_effective_config("windows", per_call)

        assert effective.block_telemetry is False, "an explicitly-set falsy value must be honored and never treated as unspecified"

    def test_specified_check_compares_against_the_class_default_not_the_stored_default(self) -> None:
        """A field is "unspecified" relative to SandboxConfig's own default, not the manager's current stored default.

        ``network_enabled``'s class default is ``False``. ``per_call`` here
        mirrors a caller that never touched ``network_enabled`` (so it sits at
        that same class default), while the operator has configured a stored
        default of ``True``. The stored default must fill the field in.
        """
        stored_defaults = SandboxConfig(network_enabled=True)
        manager = _ConfigMergeManager(default_config=stored_defaults)

        per_call = SandboxConfig(network_enabled=False)

        effective = manager.resolve_effective_config("windows", per_call)

        assert effective.network_enabled is True, (
            "network_enabled was left at SandboxConfig's class default (False) by the caller; "
            "the manager's stored default (True) must fill it in rather than being shadowed by it"
        )
