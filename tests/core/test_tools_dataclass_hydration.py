# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for dataclass-typed tool-parameter hydration in execute_tool_call.

Tool-call arguments arrive as plain JSON-decoded values, so a bridge method
parameter annotated with a dataclass type is supplied by an AI/orchestrator
caller as a plain mapping rather than a real instance. Bridge methods perform
genuine attribute access on such parameters, so passing the mapping straight
through fails deep inside the call (an ``AttributeError`` on a ``dict``)
instead of at the dispatch boundary. These tests exercise the
``ToolRegistry.execute_tool_call`` dispatcher fix (Tier-1 finding #6) that
hydrates such mappings into real dataclass instances before dispatch.

A purpose-built fake bridge is used throughout rather than any real bridge's
own dataclass parameter, so these tests validate the general dispatcher
mechanism itself and do not depend on any particular bridge module's own
import shape.

Tests validate:
- A mapping supplied for a dataclass-annotated parameter reaches the bound
  method as a genuine dataclass instance, including recursive hydration of
  a nested dataclass field.
- A plain (non-dataclass-typed) parameter, and a parameter already holding a
  real dataclass instance, pass through dispatch completely unchanged.
- An invalid mapping - one naming a field the dataclass does not have, or one
  that cannot construct the target dataclass - raises ``ToolError`` rather
  than a raw ``TypeError`` or a silently passed-through dict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolDefinition, ToolError, ToolFunction, ToolName


if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class _InnerSettings:
    """Nested dataclass used to prove recursive hydration of dataclass fields.

    Attributes:
        factor: A required integer field with no default, so omitting it
            from a supplied mapping exercises the "cannot construct" path.
    """

    factor: int


@dataclass
class _OuterSettings:
    """Dataclass-typed tool parameter used across the hydration tests.

    Attributes:
        label: An arbitrary string field.
        inner: A nested dataclass field, optionally supplied as a mapping
            that must itself be hydrated into a real ``_InnerSettings``.
    """

    label: str = "default"
    inner: _InnerSettings | None = None


class _ConfigurableBridge(ToolBridgeBase):
    """Minimal bridge exposing a dataclass-typed and a plain tool parameter.

    ``configure`` mirrors the shape the Tier-1 finding #6 dispatcher fix
    targets: one parameter annotated with a dataclass type (optionally
    ``None``), and one plain ``str`` parameter used to prove non-dataclass
    parameters are left untouched by hydration.
    """

    def __init__(self) -> None:
        """Initialize the bridge with no recorded call yet."""
        super().__init__()
        self.received_label: str | None = None
        self.received_settings: _OuterSettings | None = None

    @property
    def name(self) -> ToolName:
        """Report the enum member this fake bridge registers under.

        Returns:
            ToolName: ToolName.SANDBOX.
        """
        return ToolName.SANDBOX

    @property
    def tool_definition(self) -> ToolDefinition:
        """Minimal tool definition satisfying the abstract base contract.

        Returns:
            ToolDefinition: A definition exposing the ``configure`` function.
        """
        return ToolDefinition(
            tool_name=ToolName.SANDBOX.value,
            description="Fake bridge for dataclass tool-parameter hydration tests.",
            functions=[
                ToolFunction(
                    name="configure",
                    description="Record the label and settings it was dispatched with.",
                    parameters=[],
                    returns="dict",
                ),
            ],
        )

    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initialize.

        Args:
            tool_path: Unused; accepted to satisfy the base signature.
        """

    async def shutdown(self) -> None:
        """Run the shared base-class shutdown bookkeeping."""
        await super().shutdown()

    async def is_available(self) -> bool:
        """Report unconditional availability.

        Returns:
            bool: Always True.
        """
        return True

    def configure(self, label: str, settings: _OuterSettings | None = None) -> dict[str, Any]:
        """Record the arguments this bridge method was actually invoked with.

        Args:
            label: An arbitrary plain-string parameter.
            settings: A dataclass-typed parameter that dispatch must hydrate
                from a mapping before this method receives it.

        Returns:
            dict[str, Any]: The received label and the runtime type name of
            ``settings``, so tests can assert on dispatch's behavior without
            reaching into the bridge instance.
        """
        self.received_label = label
        self.received_settings = settings
        return {"label": label, "settings_type": type(settings).__name__}


@pytest.fixture
def registry_with_bridge(tmp_path: Path) -> tuple[ToolRegistry, _ConfigurableBridge]:
    """Build a ToolRegistry with a single registered ``_ConfigurableBridge``.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        tuple[ToolRegistry, _ConfigurableBridge]: The registry and the exact
        bridge instance registered into it, for asserting on recorded state.
    """
    registry = ToolRegistry(tools_dir=tmp_path / "tools")
    bridge = _ConfigurableBridge()
    registry.register_bridge(ToolName.SANDBOX, bridge)
    return registry, bridge


@pytest.mark.asyncio
async def test_dataclass_mapping_argument_is_hydrated_into_real_instance(
    registry_with_bridge: tuple[ToolRegistry, _ConfigurableBridge],
) -> None:
    """A mapping for a dataclass-typed parameter reaches the method as a real instance.

    Also proves recursive hydration: the nested ``inner`` mapping must become
    a genuine ``_InnerSettings`` instance, not merely leave the outer
    ``_OuterSettings`` wrapper around a leftover dict.

    Falsifiability: with the ``_hydrate_dataclass_arguments`` call removed
    from ``ToolRegistry.execute_tool_call`` (confirmed by temporarily
    reverting that line during development and rerunning this scenario),
    ``bridge.received_settings`` is the raw ``dict`` instead of
    ``_OuterSettings``, failing the ``isinstance`` assertions below.

    Args:
        registry_with_bridge: Registry and bridge fixture.
    """
    registry, bridge = registry_with_bridge

    result = await registry.execute_tool_call(
        "sandbox",
        "configure",
        {"label": "case-a", "settings": {"label": "hydrated", "inner": {"factor": 7}}},
    )

    assert isinstance(bridge.received_settings, _OuterSettings), (
        f"expected a real _OuterSettings instance, got {type(bridge.received_settings).__name__}"
    )
    assert bridge.received_settings.label == "hydrated"
    assert isinstance(bridge.received_settings.inner, _InnerSettings), (
        f"expected the nested mapping to be hydrated into _InnerSettings, got {type(bridge.received_settings.inner).__name__}"
    )
    assert bridge.received_settings.inner.factor == 7
    assert result == {"label": "case-a", "settings_type": "_OuterSettings"}


@pytest.mark.asyncio
async def test_non_dataclass_argument_passes_through_unchanged(
    registry_with_bridge: tuple[ToolRegistry, _ConfigurableBridge],
) -> None:
    """A plain (non-dataclass-typed) parameter is dispatched exactly as supplied.

    Also covers omitting the dataclass-typed parameter entirely: the
    method's own default (``None``) must be used rather than hydration
    inventing a value where the caller supplied none.

    Falsifiability: a hydration implementation that (incorrectly) tries to
    coerce every mapping-shaped or missing argument would either raise here
    or replace the missing ``settings`` with something other than ``None``;
    both would fail the assertions below.

    Args:
        registry_with_bridge: Registry and bridge fixture.
    """
    registry, bridge = registry_with_bridge

    result = await registry.execute_tool_call("sandbox", "configure", {"label": "plain-value"})

    assert bridge.received_label == "plain-value"
    assert bridge.received_settings is None
    assert result == {"label": "plain-value", "settings_type": "NoneType"}


@pytest.mark.asyncio
async def test_existing_dataclass_instance_argument_passes_through_unchanged(
    registry_with_bridge: tuple[ToolRegistry, _ConfigurableBridge],
) -> None:
    """A value that is already a real dataclass instance is left untouched.

    GUI callers construct real config objects directly rather than
    supplying a mapping; dispatch must not attempt to re-hydrate (or
    reject) a value that is already an instance of the target dataclass.

    Falsifiability: an implementation that unconditionally rebuilds the
    dataclass from ``dataclasses.asdict`` (instead of checking
    ``isinstance(value, Mapping)`` first) would still pass the equality
    check but fail the stronger ``is`` identity assertion below, revealing
    that the original object was discarded and replaced with a copy.

    Args:
        registry_with_bridge: Registry and bridge fixture.
    """
    registry, bridge = registry_with_bridge
    original = _OuterSettings(label="already-real", inner=_InnerSettings(factor=3))

    result = await registry.execute_tool_call("sandbox", "configure", {"label": "x", "settings": original})

    assert bridge.received_settings is original
    assert result == {"label": "x", "settings_type": "_OuterSettings"}


@pytest.mark.asyncio
async def test_unknown_field_in_mapping_raises_tool_error(
    registry_with_bridge: tuple[ToolRegistry, _ConfigurableBridge],
) -> None:
    """A mapping naming a field the target dataclass does not have raises ToolError.

    Falsifiability: reverting the ``_hydrate_dataclass_arguments`` wiring
    makes this call succeed instead of raising (the unrecognised dict
    reaches ``configure`` unchecked and ``bridge.received_settings`` becomes
    the raw dict), failing the ``pytest.raises`` context below.

    Args:
        registry_with_bridge: Registry and bridge fixture.
    """
    registry, bridge = registry_with_bridge

    with pytest.raises(ToolError, match="unknown field"):
        await registry.execute_tool_call(
            "sandbox",
            "configure",
            {"label": "case-c", "settings": {"label": "x", "nonexistent_field": 1}},
        )
    assert bridge.received_settings is None, "the bridge method must never have been invoked with the bad mapping"


@pytest.mark.asyncio
async def test_mapping_missing_required_field_raises_tool_error(
    registry_with_bridge: tuple[ToolRegistry, _ConfigurableBridge],
) -> None:
    """A mapping that cannot construct the dataclass raises ToolError, not a raw TypeError.

    Supplies an empty mapping for the nested ``inner`` field, whose
    ``_InnerSettings.factor`` has no default: the real
    ``_InnerSettings(**{})`` construction fails with ``TypeError``, which
    dispatch must convert into a ``ToolError`` rather than letting it
    propagate raw or silently passing the incomplete dict through.

    Falsifiability: an implementation that catches ``TypeError`` and
    silently falls back to leaving the mapping un-hydrated (instead of
    re-raising as ``ToolError``) would let this call succeed with
    ``bridge.received_settings`` holding a raw dict, failing the
    ``pytest.raises`` context below.

    Args:
        registry_with_bridge: Registry and bridge fixture.
    """
    registry, bridge = registry_with_bridge

    with pytest.raises(ToolError, match="cannot construct"):
        await registry.execute_tool_call(
            "sandbox",
            "configure",
            {"label": "case-e", "settings": {"inner": {}}},
        )
    assert bridge.received_settings is None, "the bridge method must never have been invoked with an unconstructed mapping"
