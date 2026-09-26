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


def _intercept_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    module: object,
) -> list[tuple[object, ...]]:
    """Patch ``run_bridge_coroutine_logged`` on ``module`` to capture calls instead of dispatching them.

    Args:
        monkeypatch: pytest monkeypatch fixture used to install the patch.
        module: Module (``sandbox_panel``) whose ``run_bridge_coroutine_logged``
            binding is intercepted.

    Returns:
        list[tuple[object, ...]]: List that accumulates the positional arguments
        of each intercepted call, in call order.
    """
    calls: list[tuple[object, ...]] = []

    def _capture(*args: object, **kwargs: object) -> None:
        del kwargs
        calls.append(args)

    monkeypatch.setattr(module, "run_bridge_coroutine_logged", _capture)
    return calls


class _RecordingSandboxBridge:
    """Stand-in for ``SandboxBridge`` that records ``create()`` calls without doing real sandbox work.

    ``create`` is a plain (non-async) method so the call itself -- not some
    later await -- records the exact keyword arguments ``_on_create`` passed,
    matching what the test observes: ``run_bridge_coroutine_logged`` is
    intercepted and never actually drives the returned awaitable.
    """

    def __init__(self) -> None:
        """Initialize with an empty call log."""
        self.create_calls: list[dict[str, object]] = []
        self.last_create_result: object | None = None

    def create(self, **kwargs: object) -> object:
        """Record the keyword arguments and return a distinct per-call result object.

        Args:
            **kwargs: Keyword arguments forwarded by ``SandboxPanel._on_create``.

        Returns:
            object: A fresh sentinel object identifying this specific call, so
            tests can confirm it is exactly what gets handed to the dispatcher.
        """
        self.create_calls.append(kwargs)
        result = object()
        self.last_create_result = result
        return result


def _call_config(panel: SandboxPanel) -> dict[str, object]:
    """Build the create-config mapping using the panel's own production builder.

    Deriving the expected keyword arguments from the real builder keeps the
    wiring assertions strict about dropped or extra keys while remaining correct
    as new ``SandboxConfig`` fields are added, instead of hard-coding a key list
    that silently rots.

    Args:
        panel: Panel whose configuration builder is invoked.

    Returns:
        dict[str, object]: The mapping ``_on_create`` splats into ``bridge.create``.
    """
    builder = _get_private(panel, "_sandbox_create_config")
    assert callable(builder), "SandboxPanel._sandbox_create_config must be callable"
    return cast("dict[str, object]", builder())


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
        bridge = _RecordingSandboxBridge()
        _set_private(panel, "_bridge", bridge)

        timeout_spin = cast("QSpinBox", _get_private(panel, "_timeout_spin"))
        timeout_spin.setValue(9999)
        memory_spin = cast("QSpinBox", _get_private(panel, "_memory_limit_spin"))
        memory_spin.setValue(65536)
        network_check = cast("QCheckBox", _get_private(panel, "_network_enabled_check"))
        network_check.setChecked(True)

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(panel, "_on_create")

        assert dispatch_args, "run_bridge_coroutine_logged must be called by _on_create"
        assert dispatch_args[0][0] is bridge.last_create_result, (
            f"first positional arg must be the result from bridge.create; got {dispatch_args[0][0]!r}"
        )
        assert len(bridge.create_calls) == 1
        kwargs = bridge.create_calls[0]
        assert kwargs["timeout_seconds"] == 9999
        assert kwargs["network_enabled"] is True
        assert kwargs["memory_limit_mb"] == 65536
        expected = {"sandbox_type": "windows", "qemu_config": None, **_call_config(panel)}
        assert kwargs == expected, (
            f"_on_create must forward exactly the panel's config; mismatched keys: {sorted(set(expected) ^ set(kwargs))}"
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
        bridge = _RecordingSandboxBridge()
        _set_private(panel, "_bridge", bridge)

        dispatch_args = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(panel, "_on_create")

        assert dispatch_args
        assert len(bridge.create_calls) == 1
        kwargs = bridge.create_calls[0]
        assert kwargs["timeout_seconds"] == 300
        assert kwargs["network_enabled"] is False
        assert kwargs["memory_limit_mb"] == 2048
        expected = {"sandbox_type": "windows", "qemu_config": None, **_call_config(panel)}
        assert kwargs == expected, (
            f"_on_create must forward exactly the panel's default config; mismatched keys: {sorted(set(expected) ^ set(kwargs))}"
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

        dispatch_calls = _intercept_dispatch(monkeypatch, _sandbox_panel_mod)

        _invoke(panel, "_on_create")

        assert not dispatch_calls, "bridge.create must not be dispatched when no bridge is configured"
