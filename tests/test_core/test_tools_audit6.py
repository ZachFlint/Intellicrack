# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit6 CORE-D regression tests for ``intellicrack.core.tools``.

Exercises:
    * F-0017 - ``CutterBridge`` is auto-initialised in ``ToolRegistry.initialize``.
    * F-0018 - ``tool_status_check_failed`` log uses non-clashing keys and
      serialises the enum value.
    * F-0023 - ``ToolRegistry.shutdown`` clears ``self._bridges``.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.core.tools import ToolRegistry, ToolStatus
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path


class _FakeState:
    """Minimal stand-in for ``BridgeState`` exposed via ``bridge.state``.

    Attributes:
        connected: Connection flag tested by ``ToolRegistry.get_status``.
        last_error: Recorded error string.
    """

    connected: bool
    last_error: str | None

    def __init__(self) -> None:
        """Initialise with default disconnected state."""
        self.connected = False
        self.last_error = None


class _FailingBridge:
    """Bridge whose ``is_available`` always raises ``RuntimeError``.

    Used to exercise ``ToolRegistry.get_status``'s exception branch.
    """

    def __init__(self) -> None:
        """Initialise with a fresh fake state."""
        self.state: _FakeState = _FakeState()

    async def is_available(self) -> bool:
        """Always raise to drive the ``except`` branch.

        Returns:
            bool: Never returns; declared to satisfy the bridge protocol.

        Raises:
            RuntimeError: Always raised to simulate a bridge failure.
        """
        msg = "bridge unavailable for test"
        raise RuntimeError(msg)


class _ShutdownableBridge:
    """Bridge that records ``shutdown`` invocations and exposes init flag."""

    def __init__(self) -> None:
        """Initialise with shutdown counter and init flag."""
        self.shutdown_count: int = 0
        self.initialize_called: bool = False
        self.state: _FakeState = _FakeState()

    async def initialize(self, _tool_path: Path | None = None) -> None:
        """Mark the bridge as initialised.

        Args:
            _tool_path: Ignored optional tool path.
        """
        self.initialize_called = True

    async def shutdown(self) -> None:
        """Increment the shutdown counter."""
        self.shutdown_count += 1

    async def is_available(self) -> bool:
        """Return whether ``initialize`` has been called.

        Returns:
            bool: True when ``initialize_called`` was set.
        """
        return self.initialize_called


def _registry(tmp_path: Path) -> ToolRegistry:
    """Construct a ToolRegistry rooted at ``tmp_path``.

    Args:
        tmp_path: pytest's temporary directory.

    Returns:
        ToolRegistry: Fresh registry instance.
    """
    return ToolRegistry(tmp_path)


def _bridges(registry: ToolRegistry) -> dict[ToolName, Any]:
    """Return the registry's internal ``_bridges`` mapping.

    Args:
        registry: Registry instance to inspect.

    Returns:
        dict[ToolName, Any]: Live mapping of registered bridges.
    """
    return cast("dict[ToolName, Any]", getattr(registry, "_bridges"))


class TestF0017CutterAutoInit:
    """Cutter bridge must be initialised by ``ToolRegistry.initialize``."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_cutter_in_initialize_targets_set(
        tmp_path: Path,
    ) -> None:
        """The CUTTER bridge must be in the auto-init target set.

        Asserts the registry exposes a ``_LOCAL_INIT_TOOLS`` membership that
        includes ``ToolName.CUTTER``. Registry initialisation drives Cutter
        through the same auto-init path used by PROCESS, FRIDA, SANDBOX, and
        HEX_EDITOR.

        Args:
            tmp_path: pytest temporary directory.
        """
        del tmp_path
        import importlib  # noqa: PLC0415

        tools_module = importlib.import_module("intellicrack.core.tools")
        local_init_tools = cast(
            "frozenset[ToolName]",
            getattr(tools_module, "_LOCAL_INIT_TOOLS"),
        )
        assert ToolName.CUTTER in local_init_tools, f"_LOCAL_INIT_TOOLS must contain Cutter; got {local_init_tools!r}"

    @staticmethod
    @pytest.mark.asyncio
    async def test_cutter_initialize_invoked_on_registry_initialize(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``CutterBridge.initialize`` must run when the registry initialises.

        Patches each bridge class so importing them returns a fast no-op
        instance whose ``initialize`` records the call. This proves the
        registry auto-initialise loop visits the Cutter slot.

        Args:
            tmp_path: pytest temporary directory.
            monkeypatch: pytest monkeypatch fixture.
        """
        recorded: dict[str, bool] = {tool.value: False for tool in ToolName}

        def _make_bridge_class(tool: ToolName) -> type[_ShutdownableBridge]:
            class _Bridge(_ShutdownableBridge):
                async def initialize(self, _tool_path: Path | None = None) -> None:
                    recorded[tool.value] = True
                    self.initialize_called = True

            _Bridge.__name__ = f"_{tool.value.title()}Bridge"
            return _Bridge

        process_module_path = "intellicrack.bridges.process"
        process_bridge_cls = _make_bridge_class(ToolName.PROCESS)
        frida_bridge_cls = _make_bridge_class(ToolName.FRIDA)
        ghidra_bridge_cls = _make_bridge_class(ToolName.GHIDRA)
        cutter_bridge_cls = _make_bridge_class(ToolName.CUTTER)
        x64dbg_bridge_cls = _make_bridge_class(ToolName.X64DBG)
        sandbox_bridge_cls = _make_bridge_class(ToolName.SANDBOX)
        hex_bridge_cls = _make_bridge_class(ToolName.HEX_EDITOR)

        import importlib  # noqa: PLC0415

        real_import_module = importlib.import_module
        replacement_classes: dict[tuple[str, str], type[_ShutdownableBridge]] = {
            (process_module_path, "ProcessBridge"): process_bridge_cls,
            ("intellicrack.bridges.frida_bridge", "FridaBridge"): frida_bridge_cls,
            ("intellicrack.bridges.ghidra", "GhidraBridge"): ghidra_bridge_cls,
            ("intellicrack.bridges.cutter", "CutterBridge"): cutter_bridge_cls,
            ("intellicrack.bridges.x64dbg", "X64DbgBridge"): x64dbg_bridge_cls,
            ("intellicrack.bridges.sandbox_bridge", "SandboxBridge"): sandbox_bridge_cls,
            ("intellicrack.bridges.hex_editor", "HexEditorBridge"): hex_bridge_cls,
        }

        class _Stub:
            def __init__(self, mapping: dict[str, type[_ShutdownableBridge]]) -> None:
                for key, value in mapping.items():
                    setattr(self, key, value)

        def _patched_import_module(name: str, package: str | None = None) -> object:
            cls_for_module = {module: cls_obj for (module, _name), cls_obj in replacement_classes.items()}
            if name in cls_for_module:
                attrs = {cls_attr: cls_obj for (module, cls_attr), cls_obj in replacement_classes.items() if module == name}
                return _Stub(attrs)
            return real_import_module(name, package)

        monkeypatch.setattr(importlib, "import_module", _patched_import_module)

        registry = _registry(tmp_path)
        await registry.initialize()

        assert recorded[ToolName.CUTTER.value] is True, f"CutterBridge.initialize must be invoked; recorded={recorded!r}"


class TestF0018ToolStatusLogging:
    """``tool_status_check_failed`` must use non-clashing key and enum value."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_tool_status_failure_log_serialises_enum_value(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Failed status checks must record ``tool_name`` as the enum value.

        Patches ``_logger.warning`` on the ``intellicrack.core.tools`` module
        so the test can inspect the structured payload directly without
        depending on global structlog/stdlib configuration set up by other
        test modules.

        Args:
            tmp_path: pytest temporary directory.
            monkeypatch: pytest monkeypatch fixture.
        """
        import importlib  # noqa: PLC0415

        tools_module = importlib.import_module("intellicrack.core.tools")
        captured: list[tuple[str, dict[str, object]]] = []

        original_logger = tools_module._logger

        class _ProbeLogger:
            def __init__(self) -> None:
                pass

            def warning(self, event: str, **kwargs: object) -> None:
                captured.append((event, dict(kwargs)))
                original_logger.warning(event, **kwargs)

            def debug(self, event: str, **kwargs: object) -> None:
                original_logger.debug(event, **kwargs)

            def info(self, event: str, **kwargs: object) -> None:
                original_logger.info(event, **kwargs)

            def error(self, event: str, **kwargs: object) -> None:
                original_logger.error(event, **kwargs)

            def exception(self, event: str, **kwargs: object) -> None:
                original_logger.error(event, **kwargs)

        monkeypatch.setattr(tools_module, "_logger", _ProbeLogger())

        registry = _registry(tmp_path)
        bridges_map = _bridges(registry)
        bridges_map[ToolName.GHIDRA] = _FailingBridge()

        status: ToolStatus = await registry.get_status(ToolName.GHIDRA)

        assert status.available is False
        assert status.connected is False

        matching = [(event, payload) for event, payload in captured if event == "tool_status_check_failed"]
        assert matching, f"expected tool_status_check_failed log; got events={[e for e, _ in captured]!r}"

        _, payload = matching[0]
        assert "tool_name" in payload, f"log payload must contain 'tool_name'; got keys={list(payload.keys())!r}"
        assert payload["tool_name"] == ToolName.GHIDRA.value, (
            f"tool_name must serialise the enum value 'ghidra'; got {payload['tool_name']!r}"
        )
        assert payload.get("tool_name") != ToolName.GHIDRA, "tool_name must be the value, not the enum object"

    @staticmethod
    @pytest.mark.asyncio
    async def test_tool_status_failure_log_uses_non_clashing_key(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Log payload must not pass bare ``name=`` (clashes with LogRecord.name).

        Using ``tool_name`` (instead of ``name``) avoids ruff G101 and the
        stdlib ``LogRecord.name`` attribute clash flagged in CLAUDE.md memory.

        Args:
            tmp_path: pytest temporary directory.
            monkeypatch: pytest monkeypatch fixture.
        """
        import importlib  # noqa: PLC0415

        tools_module = importlib.import_module("intellicrack.core.tools")
        captured: list[tuple[str, dict[str, object]]] = []

        original_logger = tools_module._logger

        class _ProbeLogger:
            def __init__(self) -> None:
                pass

            def warning(self, event: str, **kwargs: object) -> None:
                captured.append((event, dict(kwargs)))
                original_logger.warning(event, **kwargs)

            def debug(self, event: str, **kwargs: object) -> None:
                original_logger.debug(event, **kwargs)

            def info(self, event: str, **kwargs: object) -> None:
                original_logger.info(event, **kwargs)

            def error(self, event: str, **kwargs: object) -> None:
                original_logger.error(event, **kwargs)

            def exception(self, event: str, **kwargs: object) -> None:
                original_logger.error(event, **kwargs)

        monkeypatch.setattr(tools_module, "_logger", _ProbeLogger())

        registry = _registry(tmp_path)
        bridges_map = _bridges(registry)
        bridges_map[ToolName.GHIDRA] = _FailingBridge()

        await registry.get_status(ToolName.GHIDRA)

        matching = [(event, payload) for event, payload in captured if event == "tool_status_check_failed"]
        assert matching, "expected tool_status_check_failed log"

        for _, payload in matching:
            assert "name" not in payload, f"log payload must not use bare 'name' key (clashes with LogRecord.name); got: {payload!r}"
            assert "tool_name" in payload, f"log payload must use 'tool_name' instead of 'name'; got: {payload!r}"


class TestF0023ShutdownClearsBridges:
    """``ToolRegistry.shutdown`` must empty ``self._bridges``."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_shutdown_clears_bridges(
        tmp_path: Path,
    ) -> None:
        """After ``shutdown``, ``_bridges`` must be empty.

        Args:
            tmp_path: pytest temporary directory.
        """
        registry = _registry(tmp_path)
        bridges_map = _bridges(registry)
        bridges_map[ToolName.PROCESS] = _ShutdownableBridge()
        bridges_map[ToolName.FRIDA] = _ShutdownableBridge()

        assert len(bridges_map) == 2

        await registry.shutdown()

        assert len(_bridges(registry)) == 0
        assert getattr(registry, "_initialized") is False

    @staticmethod
    @pytest.mark.asyncio
    async def test_shutdown_clears_bridges_even_when_one_raises(
        tmp_path: Path,
    ) -> None:
        """Failures in one bridge must not prevent ``_bridges`` clearing.

        Args:
            tmp_path: pytest temporary directory.
        """
        shutdown_failure_message = "simulated shutdown failure"

        class _RaisingBridge(_ShutdownableBridge):
            """Bridge whose shutdown raises ToolError."""

            async def shutdown(self) -> None:
                """Raise ToolError to simulate a bridge cleanup failure.

                Raises:
                    ToolError: Always raised to exercise the failure branch.
                """
                raise ToolError(shutdown_failure_message)

        registry = _registry(tmp_path)
        bridges_map = _bridges(registry)
        bridges_map[ToolName.PROCESS] = _ShutdownableBridge()
        bridges_map[ToolName.FRIDA] = _RaisingBridge()

        await registry.shutdown()

        assert len(_bridges(registry)) == 0


class TestF0017InitializeToolHandlesCutter:
    """``ToolRegistry.initialize_tool`` must accept Cutter without installer."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_initialize_tool_for_cutter_uses_local_init(
        tmp_path: Path,
    ) -> None:
        """Cutter must use the local-init code path, not installer.ensure_tool.

        Args:
            tmp_path: pytest temporary directory.
        """
        registry = _registry(tmp_path)
        cutter = _ShutdownableBridge()
        bridges_map = _bridges(registry)
        bridges_map[ToolName.CUTTER] = cutter

        installer = getattr(registry, "_installer")

        async def _explode(_name: ToolName) -> Path:
            await asyncio.sleep(0)
            msg = "installer should not be invoked for cutter"
            raise AssertionError(msg)

        ensure_tool: Callable[[ToolName], Awaitable[Path]] = _explode
        installer.ensure_tool = ensure_tool

        result = await registry.initialize_tool(ToolName.CUTTER)

        assert result is True
        assert cutter.initialize_called is True
