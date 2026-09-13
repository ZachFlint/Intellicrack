# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness remediation gates for the SANDBOX isolation-extras slice (L1 + L2 + L3).

Covers agent-10 (``audit/bridge-completeness/agent-10-sandbox-process.md``) row 17 and
Prioritized-gap-list item 2: ``sandbox.create``/``sandbox.restart`` (the AI tool-calling
path) and the per-instance panel toolbar (the GUI path) could set none of
``SandboxConfig``'s 7 isolation-extras fields -- ``clipboard_enabled``, ``audio_enabled``,
``video_enabled``, ``printer_enabled``, ``shared_folders``, ``startup_commands``,
``environment_variables`` -- nor did the panel expose a per-instance ``block_telemetry``
override, despite every field already being fully consumed by ``WindowsSandbox``.

* L1 -- ``SandboxBridge.create``/``restart`` thread all 7 fields into a real
  ``SandboxConfig`` passed to the manager, with ``SandboxConfig``'s own documented
  defaults when a caller supplies none.
* L2 -- ``sandbox.create``/``sandbox.restart`` declare matching ``ToolParameter`` entries
  for all 7 fields, with the ``shared_folders`` array-of-objects schema and the
  ``environment_variables`` object schema carrying no illegal ``dict`` default.
* L3 -- the panel's new "Isolation Extras" checkboxes and delimited text fields flow
  through ``_sandbox_create_config()`` into the real ``SandboxBridge.create`` call made
  by ``_on_create``.
"""

from __future__ import annotations

import inspect
import os
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QApplication, QCheckBox, QLineEdit

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.ui.panels import sandbox_panel as _sandbox_panel_mod
from intellicrack.ui.panels.sandbox_panel import SandboxPanel
from tests.sandbox.conftest import InMemorySandbox, StubInstance, StubManager


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from intellicrack.sandbox.base import SandboxConfig
    from intellicrack.sandbox.manager import SandboxManager

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a session-scoped QApplication.

    Qt requires exactly one QApplication per process.

    Yields:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def sandbox_panel(qapp: QApplication) -> SandboxPanel:
    """Create a SandboxPanel instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        SandboxPanel: A fresh SandboxPanel widget.
    """
    assert isinstance(qapp, QApplication)
    return SandboxPanel()


def _set_private(widget: object, attr_name: str, value: object) -> None:
    """Assign a value to a named private attribute of a widget under test.

    Used to wire test doubles (e.g. a mock bridge) into private collaborator
    slots without a direct private-attribute assignment expression that would
    fight the widget's declared attribute type.

    Args:
        widget: Widget instance to mutate.
        attr_name: Attribute name to set.
        value: Value to assign.
    """
    setattr(widget, attr_name, value)


def _get_private(widget: object, attr_name: str) -> object:
    """Read a named private attribute of a widget under test.

    Args:
        widget: Widget instance to read from.
        attr_name: Attribute name to read.

    Returns:
        object: The current value of the attribute.
    """
    return getattr(widget, attr_name)


def _invoke(widget: object, method_name: str) -> None:
    """Invoke a named zero-argument handler method on a widget.

    Args:
        widget: Widget whose handler is invoked.
        method_name: Name of the handler method to call.
    """
    handler = getattr(widget, method_name)
    assert callable(handler), f"{type(widget).__name__}.{method_name} must be callable"
    handler()


def _call_private(widget: object, method_name: str) -> object:
    """Invoke a named zero-argument method on a widget and return its result.

    Args:
        widget: Widget whose method is invoked.
        method_name: Name of the method to call.

    Returns:
        object: The method's return value.
    """
    method = getattr(widget, method_name)
    assert callable(method), f"{type(widget).__name__}.{method_name} must be callable"
    return method()


class _ConfigRecordingManager(StubManager):
    """``StubManager`` variant that threads a real ``SandboxConfig`` into created/restarted sandboxes.

    Overrides both ``create()`` and ``restart()`` directly -- unlike
    ``test_sandbox_l1_l2.py``'s ``_ConfigRecordingManager``, which only overrides
    ``create()`` and relies on ``StubManager.restart()``'s internal delegation through
    ``self.create()`` -- so this item's ``restart()`` isolation-extras coverage has its
    own direct recording point rather than depending on that delegation. Real VM
    provisioning (``WindowsSandbox``/``QEMUSandbox`` availability probing and startup) is
    the genuine external boundary this test cannot cross inside the sandbox environment,
    so this fake manager stands in for the manager layer only; ``SandboxBridge.create``/
    ``restart``'s own parameter-to-``SandboxConfig`` construction executes for real and is
    what this test falsifies.
    """

    def __init__(self, instances: dict[str, StubInstance] | None = None) -> None:
        """Initialise with optional pre-populated instances and no recorded config.

        Args:
            instances: Optional pre-populated instance dict, so a restart test can
                target an existing instance.
        """
        super().__init__(instances)
        self.last_config: SandboxConfig | None = None

    async def create(
        self,
        sandbox_type: str = "windows",
        config: SandboxConfig | None = None,
        binary_path: Path | None = None,
        qemu_config: object = None,
        *,
        auto_start: bool = True,
    ) -> StubInstance:
        """Record ``config`` before delegating to the real in-memory instance creation.

        Args:
            sandbox_type: Type of sandbox.
            config: Configuration forwarded by the caller; recorded on ``self.last_config``.
            binary_path: Optional binary path.
            qemu_config: Optional QEMU config (unused).
            auto_start: Whether to auto-start.

        Returns:
            StubInstance: Created instance.
        """
        self.last_config = config
        return await super().create(sandbox_type, config, binary_path, qemu_config, auto_start=auto_start)

    async def restart(
        self,
        instance_id: str,
        config: SandboxConfig | None = None,
        qemu_config: object = None,
    ) -> StubInstance:
        """Record ``config`` before delegating to the real in-memory restart.

        Args:
            instance_id: Identifier of the instance to replace.
            config: Configuration forwarded by the caller; recorded on ``self.last_config``.
            qemu_config: Optional QEMU config (unused).

        Returns:
            StubInstance: The replacement instance.
        """
        self.last_config = config
        return await super().restart(instance_id, config, qemu_config)


class TestSandboxIsolationExtrasCreateRestartL1:
    """L1: create()/restart() thread all 7 isolation-extras fields into a real SandboxConfig.

    Falsified by: deleting any one of the 7 isolation-extras keyword arguments from
    create()'s or restart()'s ``SandboxConfig(...)`` construction (or from the method
    signature itself) turns the corresponding assertion -- or the call itself -- red.
    """

    @pytest.mark.asyncio
    async def test_create_threads_isolation_extras_into_config(self, tmp_path: Path) -> None:
        """create() builds a SandboxConfig with every caller-supplied isolation-extras value.

        Args:
            tmp_path: Pytest-provided real directory used as the shared-folder input.
        """
        manager = _ConfigRecordingManager()
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        await bridge.create(
            sandbox_type="windows",
            clipboard_enabled=True,
            audio_enabled=True,
            video_enabled=True,
            printer_enabled=True,
            shared_folders=[{"host_path": str(tmp_path), "read_only": True}],
            startup_commands=["echo hello"],
            environment_variables={"FOO": "bar"},
        )

        cfg = manager.last_config
        assert cfg is not None
        assert cfg.clipboard_enabled is True
        assert cfg.audio_enabled is True
        assert cfg.video_enabled is True
        assert cfg.printer_enabled is True
        assert cfg.shared_folders == [(tmp_path, f"C:\\Shared\\{tmp_path.name}", True)]
        assert cfg.startup_commands == ["echo hello"]
        assert cfg.environment_variables == {"FOO": "bar"}

    @pytest.mark.asyncio
    async def test_create_defaults_isolation_extras_when_unspecified(self) -> None:
        """create() with no isolation-extras kwargs builds a SandboxConfig with SandboxConfig's own defaults."""
        manager = _ConfigRecordingManager()
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        await bridge.create(sandbox_type="windows")

        cfg = manager.last_config
        assert cfg is not None
        assert cfg.clipboard_enabled is False
        assert cfg.audio_enabled is False
        assert cfg.video_enabled is False
        assert cfg.printer_enabled is False
        assert cfg.shared_folders == []
        assert cfg.startup_commands == []
        assert cfg.environment_variables == {}

    @pytest.mark.asyncio
    async def test_restart_threads_isolation_extras_into_config(self, tmp_path: Path) -> None:
        """restart() builds a replacement SandboxConfig with every caller-supplied isolation-extras value.

        Args:
            tmp_path: Pytest-provided real directory used as the shared-folder input.
        """
        sandbox = InMemorySandbox()
        instance = StubInstance(sandbox, "windows", instance_id="windows-isolation-001")
        manager = _ConfigRecordingManager({"windows-isolation-001": instance})
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        await bridge.restart(
            "windows-isolation-001",
            clipboard_enabled=True,
            audio_enabled=True,
            video_enabled=True,
            printer_enabled=True,
            shared_folders=[{"host_path": str(tmp_path), "read_only": True}],
            startup_commands=["echo hello"],
            environment_variables={"FOO": "bar"},
        )

        cfg = manager.last_config
        assert cfg is not None
        assert cfg.clipboard_enabled is True
        assert cfg.audio_enabled is True
        assert cfg.video_enabled is True
        assert cfg.printer_enabled is True
        assert cfg.shared_folders == [(tmp_path, f"C:\\Shared\\{tmp_path.name}", True)]
        assert cfg.startup_commands == ["echo hello"]
        assert cfg.environment_variables == {"FOO": "bar"}


class TestSandboxIsolationExtrasToolDefL2:
    """L2: sandbox.create/sandbox.restart declare all 7 isolation-extras ToolParameters.

    Falsified by: deleting any one of the 7 isolation-extras ``ToolParameter`` blocks from
    either function's ``parameters=[...]`` turns ``test_declares_all_isolation_extras_params``
    red for that function, and also turns the pre-existing
    ``test_sandbox_create_restart_run_binary_params_l2.py::test_declared_params_exactly_match_method_signature``
    red, since the declared set would no longer equal the real method signature.
    """

    @pytest.mark.parametrize(
        ("tool_name", "method_name"),
        [("sandbox.create", "create"), ("sandbox.restart", "restart")],
    )
    def test_declares_all_isolation_extras_params(self, tool_name: str, method_name: str) -> None:
        """Declared params include all 7 isolation-extras names and match the real signature exactly.

        Args:
            tool_name: Full dotted tool function name (e.g. "sandbox.create").
            method_name: Real bridge method name the tool function dispatches to.
        """
        bridge = SandboxBridge()
        func = next(f for f in bridge.tool_definition.functions if f.name == tool_name)
        declared = {p.name for p in func.parameters}
        expected = {
            "clipboard_enabled",
            "audio_enabled",
            "video_enabled",
            "printer_enabled",
            "shared_folders",
            "startup_commands",
            "environment_variables",
        }
        assert expected.issubset(declared), f"{tool_name} missing {expected - declared}"

        real = {n for n in inspect.signature(getattr(bridge, method_name)).parameters if n != "self"}
        assert declared == real

    def test_shared_folders_item_schema(self) -> None:
        """shared_folders is declared as an array of objects with host_path required, read_only optional."""
        bridge = SandboxBridge()
        func = next(f for f in bridge.tool_definition.functions if f.name == "sandbox.create")
        param = next(p for p in func.parameters if p.name == "shared_folders")
        assert param.items_type == "object"

        item_properties = param.item_properties
        assert item_properties is not None
        by_name = {p.name: p for p in item_properties}
        assert by_name["host_path"].required is True
        assert by_name["read_only"].required is False

    def test_environment_variables_param_has_no_dict_default(self) -> None:
        """environment_variables carries no default at all (ToolParameter.default has no dict member)."""
        bridge = SandboxBridge()
        func = next(f for f in bridge.tool_definition.functions if f.name == "sandbox.create")
        param = next(p for p in func.parameters if p.name == "environment_variables")
        assert param.default is None


class TestSandboxIsolationExtrasPanelL3:
    """L3: the panel's isolation-extras widgets flow into the real SandboxBridge.create call.

    Falsified by: commenting out any one of the 8 new-key assignments inside
    ``_sandbox_create_config()`` turns the corresponding ``kwargs[...]`` assertion -- or
    the lookup itself -- red.
    """

    def test_isolation_extras_flow_into_create_call(
        self,
        sandbox_panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Checkbox and delimited-text widget values reach bridge.create as the matching keyword arguments.

        Args:
            sandbox_panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(sandbox_panel, "_bridge", mock_bridge)

        def _noop_dispatch(*args: object, **kwargs: object) -> None:
            del args, kwargs

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _noop_dispatch)

        cast("QCheckBox", _get_private(sandbox_panel, "_block_telemetry_check")).setChecked(False)
        cast("QCheckBox", _get_private(sandbox_panel, "_clipboard_enabled_check")).setChecked(True)
        cast("QCheckBox", _get_private(sandbox_panel, "_audio_enabled_check")).setChecked(True)
        cast("QCheckBox", _get_private(sandbox_panel, "_video_enabled_check")).setChecked(True)
        cast("QCheckBox", _get_private(sandbox_panel, "_printer_enabled_check")).setChecked(True)
        cast("QLineEdit", _get_private(sandbox_panel, "_shared_folders_input")).setText(r"C:\shared\one|ro;C:\shared\two")
        cast("QLineEdit", _get_private(sandbox_panel, "_startup_commands_input")).setText("echo hi;ipconfig /all")
        cast("QLineEdit", _get_private(sandbox_panel, "_environment_variables_input")).setText("FOO=bar;BAZ=qux")

        _invoke(sandbox_panel, "_on_create")

        mock_bridge.create.assert_called_once()
        kwargs = mock_bridge.create.call_args.kwargs
        assert kwargs["block_telemetry"] is False
        assert kwargs["clipboard_enabled"] is True
        assert kwargs["audio_enabled"] is True
        assert kwargs["video_enabled"] is True
        assert kwargs["printer_enabled"] is True
        assert kwargs["shared_folders"] == [
            {"host_path": r"C:\shared\one", "read_only": True},
            {"host_path": r"C:\shared\two", "read_only": False},
        ]
        assert kwargs["startup_commands"] == ["echo hi", "ipconfig /all"]
        assert kwargs["environment_variables"] == {"FOO": "bar", "BAZ": "qux"}

    def test_sandbox_create_config_defaults_when_widgets_untouched(self, sandbox_panel: SandboxPanel) -> None:
        """_sandbox_create_config() returns SandboxConfig's own defaults for the 8 new keys before any user input.

        Args:
            sandbox_panel: SandboxPanel fixture.
        """
        config = cast("dict[str, object]", _call_private(sandbox_panel, "_sandbox_create_config"))

        assert config["block_telemetry"] is True
        assert config["clipboard_enabled"] is False
        assert config["audio_enabled"] is False
        assert config["video_enabled"] is False
        assert config["printer_enabled"] is False
        assert config["shared_folders"] == []
        assert config["startup_commands"] == []
        assert config["environment_variables"] == {}
