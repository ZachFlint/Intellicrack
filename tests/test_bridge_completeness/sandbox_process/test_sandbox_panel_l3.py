# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness remediation gates for the SANDBOX panel controls (L3).

Covers agent-10 (``audit/bridge-completeness/agent-10-sandbox-process.md``)
gap S2: the sandbox VM/environment configuration controls (timeout,
network-enabled, memory-limit) are wired into ``SandboxPanel._on_create`` and
threaded through to ``SandboxBridge.create``.

Each test patches ``run_bridge_coroutine_logged`` in the ``sandbox_panel``
module (not the bridge) and asserts the coroutine handed to it is the exact
coroutine object returned by the real ``SandboxBridge.create`` mock, called
with the exact keyword arguments read from the toolbar widgets -- a genuine
gate on the handler's wiring logic, not the bridge implementation (which has
its own dedicated L1 gate in ``test_sandbox_l1_l2.py`` driving a real
in-process ``SandboxManager``).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QApplication, QCheckBox, QSpinBox

from intellicrack.ui.panels import sandbox_panel as _sandbox_panel_mod
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Iterator

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
def panel(qapp: QApplication) -> SandboxPanel:
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


class TestSandboxConfigRowExistsL3:
    """S2: the toolbar exposes real timeout/network/memory controls, not just the sandbox-type combo."""

    def test_timeout_spin_has_expected_range_and_default(self, panel: SandboxPanel) -> None:
        """The timeout QSpinBox has the documented range and default value.

        Args:
            panel: SandboxPanel fixture.
        """
        timeout_spin = cast("QSpinBox", _get_private(panel, "_timeout_spin"))
        assert timeout_spin.minimum() == 1
        assert timeout_spin.maximum() == 86400
        assert timeout_spin.value() == 300

    def test_memory_limit_spin_has_expected_range_and_default(self, panel: SandboxPanel) -> None:
        """The memory-limit QSpinBox has the documented range and default value.

        Args:
            panel: SandboxPanel fixture.
        """
        memory_spin = cast("QSpinBox", _get_private(panel, "_memory_limit_spin"))
        assert memory_spin.minimum() == 128
        assert memory_spin.maximum() == 131072
        assert memory_spin.value() == 2048

    def test_network_enabled_checkbox_defaults_unchecked(self, panel: SandboxPanel) -> None:
        """The network-enabled checkbox defaults to unchecked (network isolated by default).

        Args:
            panel: SandboxPanel fixture.
        """
        network_check = cast("QCheckBox", _get_private(panel, "_network_enabled_check"))
        assert network_check.isChecked() is False


class TestSandboxCreateConfigWiringL3:
    """S2: _on_create threads the real toolbar widget values into bridge.create as keyword arguments."""

    def test_on_create_passes_custom_config_values_to_bridge(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_create calls bridge.create with the exact timeout/network/memory values set on the widgets.

        Falsified by: reverting ``sandbox_panel.py``'s ``_on_create`` to call
        ``self._bridge.create(sandbox_type=sandbox_type)`` without threading
        ``**config`` (the pre-remediation behaviour per audit finding S2)
        turns this red, since the mock would then be called with only
        ``sandbox_type`` and this test's keyword-argument assertion would fail.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        timeout_spin = cast("QSpinBox", _get_private(panel, "_timeout_spin"))
        timeout_spin.setValue(9999)
        memory_spin = cast("QSpinBox", _get_private(panel, "_memory_limit_spin"))
        memory_spin.setValue(65536)
        network_check = cast("QCheckBox", _get_private(panel, "_network_enabled_check"))
        network_check.setChecked(True)

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(panel, "_on_create")

        assert dispatch_args, "run_bridge_coroutine_logged must be called by _on_create"
        assert dispatch_args[0][0] is mock_bridge.create.return_value, (
            f"first positional arg must be the coroutine from bridge.create; got {dispatch_args[0][0]!r}"
        )
        mock_bridge.create.assert_called_once_with(
            sandbox_type="windows",
            timeout_seconds=9999,
            network_enabled=True,
            memory_limit_mb=65536,
        )

    def test_on_create_passes_default_config_values_unmodified(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_create with untouched widgets passes exactly the documented default values.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        mock_bridge = MagicMock()
        _set_private(panel, "_bridge", mock_bridge)

        dispatch_args: list[tuple[object, ...]] = []

        def _capture_dispatch(*args: object, **kwargs: object) -> None:
            del kwargs
            dispatch_args.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _capture_dispatch)

        _invoke(panel, "_on_create")

        assert dispatch_args
        mock_bridge.create.assert_called_once_with(
            sandbox_type="windows",
            timeout_seconds=300,
            network_enabled=False,
            memory_limit_mb=2048,
        )

    def test_on_create_no_dispatch_without_bridge(
        self,
        panel: SandboxPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_create skips dispatch entirely when no bridge is configured.

        Args:
            panel: SandboxPanel fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(panel, "_bridge", None)

        dispatch_calls: list[object] = []

        def _fail_if_dispatched(*args: object, **_kwargs: object) -> None:
            dispatch_calls.append(args)

        monkeypatch.setattr(_sandbox_panel_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        _invoke(panel, "_on_create")

        assert dispatch_calls == [], "bridge.create must not be dispatched when no bridge is configured"
