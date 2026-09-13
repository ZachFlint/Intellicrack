# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness remediation gate for the SANDBOX qemu_config slice (L2).

Covers finding T1-6a: the ``ToolFunction`` definitions for ``sandbox.create``,
``sandbox.restart``, and ``sandbox.run_binary`` omitted several parameters
their underlying async methods already accepted and the GUI already passed
correctly - most importantly ``qemu_config``, without which an
AI/orchestrator-driven QEMU sandbox could never be given a bootable disk and
the capability was unreachable through tool dispatch.

``tests/sandbox/test_sandbox_bridge.py::test_parameter_names_match_signatures``
already guards the whole bridge against *phantom* declared parameters
(``def_params.issubset(sig_params)``), but that is a one-directional check:
it never notices a real method parameter that the tool definition simply
omits, which is exactly how ``qemu_config``, ``block_telemetry``,
``companions``, ``reuse_instance``, and ``instance_id`` went missing. This
module closes that gap for the three methods this finding names, requiring
the declared parameter set to be an *exact* match for the real method
signature rather than a subset.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.types import ToolFunction


def _real_signature_params(method: Callable[..., object]) -> set[str]:
    """Return the real, non-variadic parameter names of a bound method.

    Args:
        method: Bound method to introspect.

    Returns:
        set[str]: Parameter names excluding ``self`` and any
        ``*args``/``**kwargs`` catch-alls.
    """
    sig = inspect.signature(method)
    return {
        name
        for name, param in sig.parameters.items()
        if name != "self" and param.kind not in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
    }


def _tool_function(bridge: SandboxBridge, name: str) -> ToolFunction:
    """Look up one registered ``ToolFunction`` by its full dotted name.

    Args:
        bridge: Bridge whose ``tool_definition`` is searched.
        name: Full dotted function name (for example ``"sandbox.create"``).

    Returns:
        ToolFunction: The matching function definition.
    """
    functions_by_name = {f.name: f for f in bridge.tool_definition.functions}
    return functions_by_name[name]


class TestSandboxCreateRestartRunBinaryParamCompletenessL2:
    """L2: sandbox.create/restart/run_binary declare every real method parameter.

    Falsified by: reverting any of the ``qemu_config``, ``block_telemetry``,
    ``companions``, ``reuse_instance``, or ``instance_id`` ``ToolParameter``
    additions in ``sandbox_bridge.py``'s ``tool_definition`` turns the
    corresponding parametrised case red, since the declared parameter set
    would then no longer equal the real method signature's parameter set.
    """

    @pytest.mark.parametrize(
        ("tool_name", "method_name"),
        [
            ("sandbox.create", "create"),
            ("sandbox.restart", "restart"),
            ("sandbox.run_binary", "run_binary"),
        ],
    )
    def test_declared_params_exactly_match_method_signature(self, tool_name: str, method_name: str) -> None:
        """The declared ToolParameter names are exactly the real method's parameter names.

        Args:
            tool_name: Full dotted tool function name (e.g. "sandbox.create").
            method_name: Real bridge method name the tool function dispatches to.
        """
        bridge = SandboxBridge()
        func = _tool_function(bridge, tool_name)
        method = getattr(bridge, method_name)

        declared = {p.name for p in func.parameters}
        real = _real_signature_params(method)

        assert declared == real, (
            f"{tool_name}: declared tool params do not match the real method signature "
            f"(missing from tool def: {real - declared}, declared but not real: {declared - real})"
        )

    def test_qemu_config_modeled_as_optional_object_on_all_three(self) -> None:
        """qemu_config is declared as an optional, object-typed parameter on all three functions."""
        bridge = SandboxBridge()
        for tool_name in ("sandbox.create", "sandbox.restart", "sandbox.run_binary"):
            func = _tool_function(bridge, tool_name)
            params_by_name = {p.name: p for p in func.parameters}
            assert "qemu_config" in params_by_name, f"{tool_name} must declare qemu_config"
            qemu_param = params_by_name["qemu_config"]
            assert qemu_param.type == "object", f"{tool_name}.qemu_config must be object-typed"
            assert qemu_param.required is False, f"{tool_name}.qemu_config must be optional"

    def test_block_telemetry_default_matches_method_default_true(self) -> None:
        """block_telemetry's declared default (True) matches create/restart's real default."""
        bridge = SandboxBridge()
        for tool_name, method_name in (("sandbox.create", "create"), ("sandbox.restart", "restart")):
            func = _tool_function(bridge, tool_name)
            params_by_name = {p.name: p for p in func.parameters}
            assert "block_telemetry" in params_by_name, f"{tool_name} must declare block_telemetry"
            declared_default = params_by_name["block_telemetry"].default
            real_default = inspect.signature(getattr(bridge, method_name)).parameters["block_telemetry"].default
            assert declared_default == real_default, (
                f"{tool_name}.block_telemetry declared default {declared_default!r} != real default {real_default!r}"
            )
            assert params_by_name["block_telemetry"].required is False

    def test_run_binary_time_limit_has_no_false_fixed_default(self) -> None:
        """run_binary's time_limit carries no fabricated default; it really means "use sandbox config value".

        Falsified by: restoring the prior ``default=300`` on the
        ``sandbox.run_binary`` ``time_limit`` ``ToolParameter``, which claimed
        a fixed default that never matched the real method's
        ``time_limit: int | None = None`` and contradicted the parameter's
        own description ("default: sandbox config value").
        """
        bridge = SandboxBridge()
        func = _tool_function(bridge, "sandbox.run_binary")
        params_by_name = {p.name: p for p in func.parameters}
        real_default = inspect.signature(bridge.run_binary).parameters["time_limit"].default

        assert real_default is None, "precondition: run_binary's real time_limit default is None"
        assert params_by_name["time_limit"].default == real_default
        assert params_by_name["time_limit"].default is None
