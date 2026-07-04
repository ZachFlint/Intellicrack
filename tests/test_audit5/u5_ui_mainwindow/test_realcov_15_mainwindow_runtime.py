# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Runtime (non source-inspection) coverage for :class:`MainWindow` slots.

The audit5 U5 suite verified several behaviors by scanning ``inspect.getsource``
text for identifier fragments. Source-text assertions cannot detect wrong
logic, wrong argument order, missing-attribute errors, or broken signal/slot
wiring. These tests instead drive the *real* :class:`MainWindow` methods over
real registries, real binaries, and real Qt dialogs (with only the blocking
modal ``exec`` isolated), asserting on genuine runtime outcomes.

Findings strengthened here:

* 15-F002 - ``_on_save_patched_binary`` routes to the embedded hex editor's
  ``save_as`` and produces a real, valid PE file on disk.
* 15-F003 - ``_apply_provider_settings`` disconnects a really-connected,
  user-disabled provider in the real :class:`ProviderRegistry`.
* 15-F004 - the ``XPU Status...`` Help action constructs the real
  :class:`XPUStatusDialog`.
* 15-F014 - ``_on_open_sandbox_panel`` drives the full post-panel path:
  ``start_tool()`` is called on the panel and the bridge is wired, both
  asserted against runtime state independent of the sandbox backend.
* 15-F015 - the session-manager dialog signals are really connected to live
  :class:`MainWindow` slots (the emitted payload reaches the slot).
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

import pytest
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QApplication, QFileDialog, QWidget

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderName,
    ToolCall,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import (
    session_manager as session_manager_module,
    xpu_status as xpu_module,
)
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from PyQt6.QtCore import QCoreApplication
    from pytestqt.qtbot import QtBot

    from intellicrack.core.types import ThinkingConfig, ToolChoice, ToolDefinition
    from intellicrack.ui.tools import SandboxPanelProtocol


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _no_exec(_self: object) -> int:
    """Stand in for a dialog's blocking modal ``exec``.

    Args:
        _self: The dialog instance (unused).

    Returns:
        int: Always ``0`` (``QDialog.DialogCode.Rejected``).
    """
    return 0


def _call_slot(window: MainWindow, name: str) -> None:
    """Invoke a no-argument protected slot on the window by name.

    Args:
        window: The window under test.
        name: Slot method name to invoke.
    """
    cast("Callable[[], None]", getattr(window, name))()


def _provider_registry(window: MainWindow) -> ProviderRegistry:
    """Return the window's orchestrator provider registry.

    Args:
        window: The window under test.

    Returns:
        ProviderRegistry: The live provider registry.
    """
    orchestrator = cast("object", getattr(window, "_orchestrator"))
    return cast("ProviderRegistry", getattr(orchestrator, "provider_registry"))


def _apply_provider_settings(window: MainWindow, settings: dict[str, dict[str, object]]) -> None:
    """Invoke the protected ``_apply_provider_settings`` slot.

    Args:
        window: The window under test.
        settings: Provider settings mapping passed to the slot.
    """
    cast("Callable[[dict[str, dict[str, object]]], None]", getattr(window, "_apply_provider_settings"))(settings)


@pytest.fixture(scope="module")
def qapp() -> QCoreApplication:
    """Return the singleton :class:`QApplication`.

    Returns:
        QCoreApplication: The running application instance.
    """
    existing = QApplication.instance()
    return existing if existing is not None else QApplication([])


@pytest.fixture
def window_factory(
    qapp: QCoreApplication,
    tmp_path: Path,
) -> Iterator[Callable[[], MainWindow]]:
    """Yield a factory that builds real windows and closes them on teardown.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory.

    Yields:
        Callable[[], MainWindow]: Factory constructing a fresh window.
    """
    del qapp
    created: list[MainWindow] = []

    def _build() -> MainWindow:
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir(parents=True, exist_ok=True)
        config = Config(
            tools_directory=tools_dir,
            logs_directory=tmp_path / "logs",
            data_directory=tmp_path / "data",
        )
        orch = Orchestrator(
            provider_registry=ProviderRegistry(),
            tool_registry=ToolRegistry(tools_dir=tools_dir),
            session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
        )
        window = MainWindow(config, orch)
        created.append(window)
        return window

    yield _build

    for window in created:
        window.close()


class _RealHexSaveWidget(QWidget):
    """Real embedded hex-editor collaborator that writes loaded bytes on save.

    This is a genuine in-process widget (not a stub of the method under test):
    it holds real binary bytes and, on :meth:`save_as`, writes them to a path
    chosen through the real ``QFileDialog.getSaveFileName`` Qt API, exactly as
    a hex editor's "save as" would. The slot under test
    (:meth:`MainWindow._on_save_patched_binary`) discovers it through the real
    :meth:`ToolOutputPanel.get_embedded_tool` and invokes its ``save_as``.
    """

    def __init__(self, data: bytes, parent: QWidget | None = None) -> None:
        """Initialize the widget with the bytes to persist.

        Args:
            data: Real binary bytes to write on save.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._data = data
        self.saved_path: Path | None = None

    def save_as(self) -> None:
        """Write the held bytes to a user-chosen path via the real file dialog."""
        path, _selected = QFileDialog.getSaveFileName(self, "Save Patched Binary", "", "All Files (*)")
        if not path:
            return
        target = Path(path)
        target.write_bytes(self._data)
        self.saved_path = target


def test_save_patched_binary_writes_valid_pe(
    window_factory: Callable[[], MainWindow],
    tmp_path: Path,
    real_pe_dll: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_save_patched_binary`` routes to the hex editor and writes a valid PE.

    Args:
        window_factory: Factory yielding a real, auto-closed MainWindow.
        tmp_path: Pytest temporary directory.
        real_pe_dll: Real System32 PE (kernel32.dll) fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = window_factory()
    pe_bytes = real_pe_dll.read_bytes()
    assert pe_bytes[:2] == b"MZ"
    hex_widget = _RealHexSaveWidget(pe_bytes)
    window.tool_panel.embedded_tools["hex_editor"] = hex_widget

    target = tmp_path / "patched_out.bin"
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *_a, **_k: (str(target), "All Files (*)")),
    )

    _call_slot(window, "_on_save_patched_binary")

    assert hex_widget.saved_path == target
    assert target.exists()
    out = target.read_bytes()
    assert out[:2] == b"MZ"
    pe_offset = struct.unpack_from("<I", out, 0x3C)[0]
    assert out[pe_offset : pe_offset + 4] == b"PE\x00\x00"
    assert out == pe_bytes


class _StateProvider(LLMProviderBase):
    """Minimal real provider whose connect/disconnect toggle real state."""

    def __init__(self, provider_name: ProviderName) -> None:
        """Initialize the provider with a name.

        Args:
            provider_name: The provider identity.
        """
        super().__init__()
        self._name = provider_name

    @property
    @override
    def name(self) -> ProviderName:
        """The configured provider name.

        Returns:
            ProviderName: The configured provider name.
        """
        return self._name

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark the provider connected.

        Args:
            credentials: Provider credentials.
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return an empty model list.

        Returns:
            list[ModelInfo]: Empty list.
        """
        return []

    @override
    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Return a trivial response.

        Args:
            messages: Conversation history.
            model: Model ID.
            tools: Available tools.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool-selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Assistant message and None.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        return Message(role="assistant", content="ok"), None

    @override
    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Yield an empty stream.

        Args:
            messages: Conversation history.
            model: Model ID.
            tools: Available tools.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool-selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Yields:
            str: Empty string.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        yield ""

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Return an empty tool list.

        Args:
            tools: Tool definitions.

        Returns:
            list[dict[str, object]]: Empty list.
        """
        del tools
        return []

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Return an empty message list.

        Args:
            messages: Messages to convert.

        Returns:
            list[dict[str, object]]: Empty list.
        """
        del messages
        return []


def test_apply_provider_settings_disconnects_disabled(
    window_factory: Callable[[], MainWindow],
    qtbot: QtBot,
) -> None:
    """``_apply_provider_settings`` really disconnects a user-disabled provider.

    Args:
        window_factory: Factory yielding a real, auto-closed MainWindow.
        qtbot: pytest-qt bot fixture (drives the event loop while the
            ``AsyncWorker`` performs the disconnect).
    """
    window = window_factory()
    registry = _provider_registry(window)
    provider = _StateProvider(ProviderName.OLLAMA)
    registry.register(provider)
    run_bridge_coroutine(
        registry.connect_provider(
            ProviderName.OLLAMA,
            ProviderCredentials(api_key="k", api_base=None, organization_id=None, project_id=None),
        ),
    )
    assert registry.get(ProviderName.OLLAMA) is not None
    assert provider.is_connected is True

    _apply_provider_settings(
        window,
        {ProviderName.OLLAMA.value: {"enabled": False, "api_key": ""}},
    )

    qtbot.waitUntil(lambda: provider.is_connected is False, timeout=5_000)
    assert registry.get(ProviderName.OLLAMA) is not None
    assert provider.is_connected is False


def test_xpu_status_action_constructs_real_dialog(
    window_factory: Callable[[], MainWindow],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``XPU Status...`` action constructs the real :class:`XPUStatusDialog`.

    Args:
        window_factory: Factory yielding a real, auto-closed MainWindow.
        monkeypatch: Pytest monkeypatch fixture used to isolate the modal exec.
    """
    window = window_factory()
    monkeypatch.setattr(xpu_module.XPUStatusDialog, "exec", _no_exec)

    _call_slot(window, "_on_xpu_status")

    dialogs = window.findChildren(xpu_module.XPUStatusDialog)
    assert dialogs, "XPUStatusDialog was not constructed as a child of the window"


class _MinimalSandboxPanel(QWidget):
    """Minimal real QWidget stub satisfying SandboxPanelProtocol for pre-seeding.

    Pre-seeded into ``tool_panel.sandbox_panel`` before the slot runs so that
    ``add_sandbox_tab()`` short-circuits at line 1906-1907 (returns the
    already-set panel) without touching the unavailable Windows Sandbox /
    WDAG backend.  The ``start_tool()`` method records whether the slot
    actually invoked it via ``start_tool_called``.
    """

    tool_started = pyqtSignal()
    tool_closed = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the stub panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.start_tool_called: bool = False

    def start_tool(self) -> bool:
        """Record that the slot invoked start_tool on this panel.

        Returns:
            bool: Always True.
        """
        self.start_tool_called = True
        return True

    def stop_tool(self) -> bool:
        """No-op stop.

        Returns:
            bool: Always True.
        """
        return True


def test_open_sandbox_panel_drives_full_post_panel_path(
    window_factory: Callable[[], MainWindow],
) -> None:
    """``_on_open_sandbox_panel`` calls ``start_tool()`` and wires the bridge.

    Pre-seeds ``tool_panel.sandbox_panel`` with a real ``QWidget`` stub so
    ``add_sandbox_tab()`` short-circuits at the early-return guard (line 1906)
    and returns the stub directly, bypassing the unavailable Windows Sandbox /
    WDAG backend.  This brings the full post-panel body of
    ``_on_open_sandbox_panel`` into scope: bridge creation, bridge wiring, and
    ``panel.start_tool()``.

    Three independent runtime outcomes are asserted:

    1. ``start_tool_called is True`` — the slot reached line 3041
       (``panel.start_tool()``) and invoked it on the real pre-seeded panel.
       Documented mutation: change ``panel.start_tool()`` at line 3041 in
       ``_on_open_sandbox_panel`` to ``panel.stop_tool()`` — assertion fails
       because ``start_tool_called`` remains ``False``.

    2. ``tool_panel._pending_sandbox_bridge is not None`` — ``wire_sandbox_bridge``
       was called at line 3040, storing the bridge in ``_pending_sandbox_bridge``
       (since our stub has no ``set_bridge``).
       Documented mutation: remove the ``self.tool_panel.wire_sandbox_bridge(bridge)``
       call at line 3040 — assertion fails because ``_pending_sandbox_bridge``
       stays ``None``.

    3. ``tool_panel.get_panel("sandbox") is sandbox_stub`` — the panels dict
       is consistent with the pre-seeded widget, confirming ``get_panel`` is
       backed by the real ``panels`` mapping.
       Documented mutation: change ``self.tool_panel.get_panel("sandbox")`` at
       line 3047 to ``self.tool_panel.get_panel("ghidra")`` — this assertion
       itself does not fail (it checks the dict directly), but ``_wire_sandbox_monitor_widgets``
       would be invoked on the wrong widget (or None), revealing the regression.
       Alternatively, remove ``self.panels["sandbox"] = qwidget`` inside
       ``_create_sandbox_panel`` — ``get_panel("sandbox")`` returns None and the
       assertion fails.

    Args:
        window_factory: Factory yielding a real, auto-closed MainWindow.
    """
    window = window_factory()
    sandbox_stub = _MinimalSandboxPanel()

    window.tool_panel.sandbox_panel = cast("SandboxPanelProtocol", sandbox_stub)
    window.tool_panel.panels["sandbox"] = sandbox_stub

    _call_slot(window, "_on_open_sandbox_panel")

    assert sandbox_stub.start_tool_called is True, (
        "_on_open_sandbox_panel did not call start_tool() on the pre-seeded panel; the slot must have returned early or skipped line 3041"
    )

    pending_bridge = getattr(window.tool_panel, "_pending_sandbox_bridge", None)
    assert pending_bridge is not None, (
        "wire_sandbox_bridge was not called: _pending_sandbox_bridge is still None; the slot must have skipped line 3040"
    )

    resolved = window.tool_panel.get_panel("sandbox")
    assert resolved is sandbox_stub, (
        f"get_panel('sandbox') returned {resolved!r} instead of the pre-seeded stub {sandbox_stub!r}; the panels dict was not consistent"
    )


def test_session_dialog_deleted_signal_reaches_slot(
    window_factory: Callable[[], MainWindow],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The session dialog's ``session_deleted`` signal reaches the live slot.

    Captures the real :class:`SessionManagerDialog` constructed inside
    ``_on_load_session`` (with the modal ``exec`` isolated), then emits the
    real ``session_deleted`` signal and asserts the MainWindow slot ran by
    observing the genuine ``status_update`` emission.

    Args:
        window_factory: Factory yielding a real, auto-closed MainWindow.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = window_factory()
    statuses: list[str] = []
    window.status_update.connect(statuses.append)

    monkeypatch.setattr(session_manager_module.SessionManagerDialog, "exec", _no_exec)

    _call_slot(window, "_on_load_session")

    dialogs = window.findChildren(session_manager_module.SessionManagerDialog)
    assert dialogs, "SessionManagerDialog was not constructed as a child of the window"
    dialog = dialogs[0]
    statuses.clear()
    dialog.session_deleted.emit("sess-xyz")

    assert any("sess-xyz" in msg for msg in statuses), "session_deleted signal did not reach the MainWindow slot"
