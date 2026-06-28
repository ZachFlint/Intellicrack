# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-gate tests for ToolRegistry typed getters and enum values (Group 06 Wave 5).

Covers:
  S7-16 — ``initialize_tool(GHIDRA)`` / ``initialize_tool(X64DBG)`` invokes the
           installer path and forwards the returned ``Path`` to ``bridge.initialize``.
  S7-17 — Typed getter ``ToolError`` messages contain the exact ``_ERR_BRIDGE_NA``
           constant text; ``pytest.raises(ToolError)`` without ``match=`` is insufficient.
  S8-12 — ``ConfirmationLevel`` enum member ``.value`` strings are exactly
           ``"none"`` / ``"destructive"`` / ``"all"``; complete member set verified.
  S8-13 — ``ToolChoiceMode`` enum member ``.value`` strings are exactly
           ``"auto"`` / ``"none"`` / ``"required"`` / ``"specific"``; complete
           member set verified.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Final, cast, override

import pytest

import intellicrack.core.tools as _tools_module
from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.installer import ToolInstaller
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    ConfirmationLevel,
    ToolChoiceMode,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
)


_FAKE_GHIDRA_PATH: Final[Path] = Path("ghidra_installer_sentinel")
_FAKE_X64DBG_PATH: Final[Path] = Path("x64dbg_installer_sentinel")
_ERR_BRIDGE_NA: Final[str] = cast(str, getattr(_tools_module, "_ERR_BRIDGE_NA"))
_INSTALLER_TYPE: type[ToolInstaller] = ToolInstaller


class _TestableToolRegistry(ToolRegistry):
    """ToolRegistry subclass exposing the protected _installer for test monkeypatching."""

    def get_installer(self) -> ToolInstaller:
        """Expose _installer for test monkeypatching.

        Returns:
            ToolInstaller: The installer instance owned by this registry.
        """
        return self._installer


class _StubGhidraBridge(GhidraBridge):
    """Stub GhidraBridge whose initialize() records the path it was called with.

    Prevents actual Ghidra startup while preserving the correct isinstance
    relationship for ``get_ghidra_bridge()``.
    """

    def __init__(self) -> None:
        """Initialize with no recorded path."""
        super().__init__()
        self.initialized_with: Path | None = None
        self.is_available_result: bool = True

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """Record the tool_path without starting Ghidra.

        Args:
            tool_path: Path forwarded by _initialize_tool_bridge.
        """
        self.initialized_with = tool_path

    @override
    async def shutdown(self) -> None:
        """No-op shutdown."""

    @override
    async def is_available(self) -> bool:
        """Return a configurable availability flag.

        Returns:
            bool: Value of ``is_available_result``.
        """
        return self.is_available_result


class _StubX64DbgBridge(X64DbgBridge):
    """Stub X64DbgBridge whose initialize() records the path it was called with.

    Prevents actual x64dbg startup while preserving the correct isinstance
    relationship for ``get_x64dbg_bridge()``.
    """

    def __init__(self) -> None:
        """Initialize with no recorded path."""
        super().__init__()
        self.initialized_with: Path | None = None

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """Record the tool_path without starting x64dbg.

        Args:
            tool_path: Path forwarded by _initialize_tool_bridge.
        """
        self.initialized_with = tool_path

    @override
    async def shutdown(self) -> None:
        """No-op shutdown."""

    @override
    async def is_available(self) -> bool:
        """Always available.

        Returns:
            bool: True.
        """
        return True


class _WrongTypeBridge(ToolBridgeBase):
    """Bridge of incorrect type; used to verify wrong-type typed-getter rejection."""

    @property
    @override
    def name(self) -> ToolName:
        """GHIDRA (even though this is not a GhidraBridge).

        Returns:
            ToolName: ToolName.GHIDRA.
        """
        return ToolName.GHIDRA

    @property
    @override
    def tool_definition(self) -> ToolDefinition:
        """A dummy tool definition.

        Returns:
            ToolDefinition: A minimal placeholder definition.
        """
        return ToolDefinition(
            tool_name=ToolName.GHIDRA,
            description="Wrong-type bridge for getter tests.",
            functions=[
                ToolFunction(name="ghidra.probe", description="probe", parameters=[], returns="dict"),
            ],
        )

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op."""

    @override
    async def shutdown(self) -> None:
        """No-op."""
        await super().shutdown()

    @override
    async def is_available(self) -> bool:
        """Always available.

        Returns:
            bool: True.
        """
        return True


class TestInitializeToolInstallerPath:
    """Gate for S7-16: initialize_tool(GHIDRA/X64DBG) calls installer then bridge.initialize."""

    def test_initialize_tool_ghidra_invokes_installer_and_bridge(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """initialize_tool(GHIDRA) calls ensure_tool then forwards path to bridge.initialize.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.

        Oracle: ``_StubGhidraBridge.initialized_with`` must equal the path returned
        by the monkeypatched ``ensure_tool``.  Mutation: bypassing the
        ``_initialize_tool_bridge`` call for GHIDRA leaves ``initialized_with=None``,
        failing the equality assertion.
        """
        expected_path = tmp_path / _FAKE_GHIDRA_PATH

        registry = _TestableToolRegistry(tools_dir=tmp_path / "tools")
        bridge = _StubGhidraBridge()
        registry.register_bridge(ToolName.GHIDRA, bridge)

        async def _fake_ensure_tool(tool: ToolName) -> Path:
            await asyncio.sleep(0)
            del tool
            return expected_path

        monkeypatch.setattr(registry.get_installer(), "ensure_tool", _fake_ensure_tool)

        async def _run() -> bool:
            return await registry.initialize_tool(ToolName.GHIDRA)

        success = asyncio.run(_run())

        assert success is True, f"initialize_tool(GHIDRA) should return True; got {success}"
        assert bridge.initialized_with == expected_path, (
            f"bridge.initialize not called with installer path; "
            f"initialized_with={bridge.initialized_with!r}, expected={expected_path!r}"
        )

    def test_initialize_tool_x64dbg_invokes_installer_and_bridge(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """initialize_tool(X64DBG) calls ensure_tool then forwards path to bridge.initialize.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.

        Oracle: ``_StubX64DbgBridge.initialized_with`` must equal the installer
        path.  Mutation: routing X64DBG through the local-init path (PROCESS/CUTTER
        logic) skips ``_initialize_tool_bridge`` and leaves ``initialized_with=None``.
        """
        expected_path = tmp_path / _FAKE_X64DBG_PATH

        registry = _TestableToolRegistry(tools_dir=tmp_path / "tools")
        bridge = _StubX64DbgBridge()
        registry.register_bridge(ToolName.X64DBG, bridge)

        async def _fake_ensure_tool(tool: ToolName) -> Path:
            await asyncio.sleep(0)
            del tool
            return expected_path

        monkeypatch.setattr(registry.get_installer(), "ensure_tool", _fake_ensure_tool)

        async def _run() -> bool:
            return await registry.initialize_tool(ToolName.X64DBG)

        success = asyncio.run(_run())

        assert success is True, f"initialize_tool(X64DBG) should return True; got {success}"
        assert bridge.initialized_with == expected_path, (
            f"bridge.initialize not called with installer path for X64DBG; "
            f"initialized_with={bridge.initialized_with!r}, expected={expected_path!r}"
        )

    def test_initialize_tool_returns_false_when_bridge_not_registered(
        self,
        tmp_path: Path,
    ) -> None:
        """initialize_tool returns False when no bridge is registered for the tool.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: the ``if name not in self._bridges: return False`` guard.
        Mutation: removing the guard causes a KeyError on the subsequent lookup.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")

        async def _run() -> bool:
            return await registry.initialize_tool(ToolName.GHIDRA)

        result = asyncio.run(_run())
        assert result is False


class TestTypedGetterErrorMessages:
    """Gate for S7-17: typed getters raise ToolError with exact message text."""

    def _make_empty_registry(self, tmp_path: Path) -> ToolRegistry:
        """Create a ToolRegistry with no bridges registered.

        Args:
            tmp_path: Pytest temporary directory for tools dir.

        Returns:
            ToolRegistry: Empty registry.
        """
        return ToolRegistry(tools_dir=tmp_path / "tools")

    def test_get_ghidra_bridge_raises_with_exact_message(self, tmp_path: Path) -> None:
        """get_ghidra_bridge() raises ToolError with '_ERR_BRIDGE_NA' text.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: ``_ERR_BRIDGE_NA == 'bridge not available'`` — the constant used
        in every typed getter.  Mutation: changing the error message string or
        raising a different exception type fails the match assertion.
        """
        registry = self._make_empty_registry(tmp_path)
        with pytest.raises(ToolError, match=r"bridge not available"):
            registry.get_ghidra_bridge()

    def test_get_cutter_bridge_raises_with_exact_message(self, tmp_path: Path) -> None:
        """get_cutter_bridge() raises ToolError with '_ERR_BRIDGE_NA' text.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: same constant ``_ERR_BRIDGE_NA``.
        """
        registry = self._make_empty_registry(tmp_path)
        with pytest.raises(ToolError, match=r"bridge not available"):
            registry.get_cutter_bridge()

    def test_get_process_bridge_raises_with_exact_message(self, tmp_path: Path) -> None:
        """get_process_bridge() raises ToolError with '_ERR_BRIDGE_NA' text.

        Args:
            tmp_path: Pytest temporary directory.
        """
        registry = self._make_empty_registry(tmp_path)
        with pytest.raises(ToolError, match=r"bridge not available"):
            registry.get_process_bridge()

    def test_get_x64dbg_bridge_raises_with_exact_message(self, tmp_path: Path) -> None:
        """get_x64dbg_bridge() raises ToolError with '_ERR_BRIDGE_NA' text.

        Args:
            tmp_path: Pytest temporary directory.
        """
        registry = self._make_empty_registry(tmp_path)
        with pytest.raises(ToolError, match=r"bridge not available"):
            registry.get_x64dbg_bridge()

    def test_get_sandbox_bridge_raises_with_exact_message(self, tmp_path: Path) -> None:
        """get_sandbox_bridge() raises ToolError with '_ERR_BRIDGE_NA' text.

        Args:
            tmp_path: Pytest temporary directory.
        """
        registry = self._make_empty_registry(tmp_path)
        with pytest.raises(ToolError, match=r"bridge not available"):
            registry.get_sandbox_bridge()

    def test_get_frida_bridge_raises_with_exact_message(self, tmp_path: Path) -> None:
        """get_frida_bridge() raises ToolError with '_ERR_BRIDGE_NA' text.

        Args:
            tmp_path: Pytest temporary directory.
        """
        registry = self._make_empty_registry(tmp_path)
        with pytest.raises(ToolError, match=r"bridge not available"):
            registry.get_frida_bridge()

    def test_err_bridge_na_constant_value(self) -> None:
        """_ERR_BRIDGE_NA equals 'bridge not available' exactly.

        Oracle: the constant string from tools.py used in every typed getter.
        Mutation: changing the constant to any other string fails the equality.
        """
        assert _ERR_BRIDGE_NA == "bridge not available", (
            f"_ERR_BRIDGE_NA changed from expected; got {_ERR_BRIDGE_NA!r}"
        )

    def test_wrong_type_bridge_raises_with_exact_message(self, tmp_path: Path) -> None:
        """get_ghidra_bridge() raises ToolError when a non-GhidraBridge is registered.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: the typed getter checks ``isinstance(bridge, GhidraBridge)``;
        a ``_WrongTypeBridge`` registered under GHIDRA fails this check and
        still raises ``ToolError(_ERR_BRIDGE_NA)``.  Mutation: removing the
        isinstance check allows any registered bridge to be returned, bypassing
        type safety.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        wrong_bridge = _WrongTypeBridge()
        registry.register_bridge(ToolName.GHIDRA, wrong_bridge)

        with pytest.raises(ToolError, match=r"bridge not available"):
            registry.get_ghidra_bridge()


class TestConfirmationLevelEnumValues:
    """Gate for S8-12: ConfirmationLevel member .value strings are exact wire-format constants."""

    def test_none_value(self) -> None:
        """ConfirmationLevel.NONE.value == 'none'.

        Oracle: the orchestrator wire-format string 'none' (used in session
        serialisation and configuration parsing).  Mutation: renaming the value
        to 'never' or 'disabled' breaks any code that deserialises from the
        stored string.
        """
        assert ConfirmationLevel.NONE.value == "none", (
            f"ConfirmationLevel.NONE.value={ConfirmationLevel.NONE.value!r}"
        )

    def test_destructive_value(self) -> None:
        """ConfirmationLevel.DESTRUCTIVE.value == 'destructive'.

        Oracle: wire-format constant 'destructive' used in orchestrator config
        serialisation.  Mutation: any other string breaks config round-trips.
        """
        assert ConfirmationLevel.DESTRUCTIVE.value == "destructive", (
            f"ConfirmationLevel.DESTRUCTIVE.value={ConfirmationLevel.DESTRUCTIVE.value!r}"
        )

    def test_all_value(self) -> None:
        """ConfirmationLevel.ALL.value == 'all'.

        Oracle: wire-format constant 'all' used in orchestrator config serialisation.
        """
        assert ConfirmationLevel.ALL.value == "all", (
            f"ConfirmationLevel.ALL.value={ConfirmationLevel.ALL.value!r}"
        )

    def test_complete_member_set(self) -> None:
        """ConfirmationLevel has exactly three members: NONE, DESTRUCTIVE, ALL.

        Oracle: the documented confirmation-level schema.  Mutation: adding or
        removing a member without updating this test leaves the member set
        unverified.
        """
        expected = {ConfirmationLevel.NONE, ConfirmationLevel.DESTRUCTIVE, ConfirmationLevel.ALL}
        actual = set(ConfirmationLevel)
        assert actual == expected, (
            f"ConfirmationLevel member set mismatch: {actual!r} != {expected!r}"
        )


class TestToolChoiceModeEnumValues:
    """Gate for S8-13: ToolChoiceMode member .value strings are exact wire-format constants."""

    def test_auto_value(self) -> None:
        """ToolChoiceMode.AUTO.value == 'auto'.

        Oracle: wire-format constant used in provider conversion code.
        Mutation: any other string breaks provider-specific tool-choice serialisation.
        """
        assert ToolChoiceMode.AUTO.value == "auto", (
            f"ToolChoiceMode.AUTO.value={ToolChoiceMode.AUTO.value!r}"
        )

    def test_none_value(self) -> None:
        """ToolChoiceMode.NONE.value == 'none'.

        Oracle: wire-format constant used in the orchestrator's forced-no-tools-next
        path (passing ``ToolChoice(mode=ToolChoiceMode.NONE)``).  Mutation:
        renaming to 'disabled' breaks provider serialisation.
        """
        assert ToolChoiceMode.NONE.value == "none", (
            f"ToolChoiceMode.NONE.value={ToolChoiceMode.NONE.value!r}"
        )

    def test_required_value(self) -> None:
        """ToolChoiceMode.REQUIRED.value == 'required'.

        Oracle: wire-format constant instructing providers to force tool use.
        """
        assert ToolChoiceMode.REQUIRED.value == "required", (
            f"ToolChoiceMode.REQUIRED.value={ToolChoiceMode.REQUIRED.value!r}"
        )

    def test_specific_value(self) -> None:
        """ToolChoiceMode.SPECIFIC.value == 'specific'.

        Oracle: wire-format constant instructing providers to call a named tool.
        """
        assert ToolChoiceMode.SPECIFIC.value == "specific", (
            f"ToolChoiceMode.SPECIFIC.value={ToolChoiceMode.SPECIFIC.value!r}"
        )

    def test_complete_member_set(self) -> None:
        """ToolChoiceMode has exactly four members: AUTO, NONE, REQUIRED, SPECIFIC.

        Oracle: the documented tool-choice schema.  Mutation: adding or removing
        a member without updating this test is caught here.
        """
        expected = {
            ToolChoiceMode.AUTO,
            ToolChoiceMode.NONE,
            ToolChoiceMode.REQUIRED,
            ToolChoiceMode.SPECIFIC,
        }
        actual = set(ToolChoiceMode)
        assert actual == expected, (
            f"ToolChoiceMode member set mismatch: {actual!r} != {expected!r}"
        )
