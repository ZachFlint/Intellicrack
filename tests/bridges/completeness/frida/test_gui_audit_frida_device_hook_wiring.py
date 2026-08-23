# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI-audit regression gates for the Frida panel's device selector and hook table.

These tests lock in three audit fixes in
``intellicrack.ui.panels.frida_panel``:

* M6 -- ``_on_device_changed`` must resolve the bridge device type/host from the
  combo item's ``userData`` (written by ``_populate_device_combo``), never from
  the human-readable display string. The prior code parsed the display text and
  therefore told the bridge ``connect_device("local", None)`` for every
  enumerated USB/remote device.
* stale-row -- the async hook add/remove callbacks must locate their target row
  by a stable hook identity (a pending sentinel key while installing, or the
  real hook id) at callback time, not by an index captured at request time. A
  concurrent completion or a ``get_hooks`` repopulate reorders rows, so a
  captured index edits/removes the wrong hook and desynchronises ``_hook_ids``.
* run-script-raise -- ``_on_run_script_success`` must surface an unusable script
  handle through the console/log instead of raising ``RuntimeError`` inside the
  Qt success slot (an exception that would escape the slot after the UI state
  was already reset).

The Qt-thread dispatch primitive ``run_bridge_coroutine_async`` is monkeypatched
exactly as in ``test_frida_panel_wiring.py``: the ``draining_dispatch`` fixture
runs the real bridge coroutine synchronously so real outbound arguments can be
observed, while ``capturing_dispatch`` records the dispatch without running it so
callback ordering can be driven deterministically. Neither replaces the widget's
own handler, which executes for real. A thin ``FridaPanel`` subclass exposes the
production-declared protected members through public wrappers -- the established
pattern in this package -- so basedpyright's ``reportPrivateUsage`` stays clean.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QSignalBlocker
from PyQt6.QtWidgets import QInputDialog

from intellicrack.core.types import FridaDeviceInfo, HookInfo, IntellicrackError
from intellicrack.ui.panels import async_bridge as async_bridge_module
from intellicrack.ui.panels.frida_panel import FridaPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QWidget

    from intellicrack.bridges.frida_bridge import FridaBridge

try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


_COL_ADDRESS: int = 0
_COL_MODULE: int = 1
_COL_FUNCTION: int = 2
_COL_STATUS: int = 3

_DISPATCH_EXCEPTIONS: tuple[type[BaseException], ...] = (
    IntellicrackError,
    *async_bridge_module.WORKER_DEFAULT_EXCEPTIONS,
    asyncio.CancelledError,
)


def _fixed_get_text(value: str) -> Callable[..., tuple[str, bool]]:
    """Build a ``QInputDialog.getText`` replacement returning a fixed accepted value.

    Args:
        value: The text the stand-in dialog reports the user entered.

    Returns:
        Callable[..., tuple[str, bool]]: A drop-in for ``QInputDialog.getText``
        that ignores its arguments and returns ``(value, True)``.
    """

    def _impl(*args: object, **kwargs: object) -> tuple[str, bool]:
        del args, kwargs
        return (value, True)

    return _impl


class _TestFridaPanel(FridaPanel):
    """FridaPanel subclass exposing device/hook internals via public wrappers."""

    def populate_devices(self, devices: list[FridaDeviceInfo]) -> None:
        """Drive the real device-combo population handler.

        Args:
            devices: Enumerated device records to render into the combo.
        """
        self._populate_device_combo(devices)

    def seed_device_items(self, items: list[tuple[str, object]]) -> None:
        """Replace the combo contents with explicit display/userData pairs.

        Args:
            items: ``(display_text, user_data)`` pairs to add, signals blocked
                so no premature device switch is triggered during setup.
        """
        with QSignalBlocker(self._device_combo):
            self._device_combo.clear()
            for display, data in items:
                self._device_combo.addItem(display, data)

    def select_device_index(self, index: int) -> None:
        """Select a combo row as a user click would, firing the change signal.

        Args:
            index: Zero-based combo index to make current.
        """
        self._device_combo.setCurrentIndex(index)

    def invoke_on_add_hook(self) -> None:
        """Invoke the real "Add Hook" toolbar handler."""
        self._on_add_hook()

    def invoke_hook_installed(self, pending_key: str, target: str, hook_info: HookInfo) -> None:
        """Invoke the real hook-installed success callback.

        Args:
            pending_key: Sentinel key stored in the pending hook row.
            target: Original hook target string.
            hook_info: Real HookInfo the bridge would have returned.
        """
        self._on_hook_installed(pending_key, target, hook_info)

    def invoke_hook_install_error(self, pending_key: str, exc: Exception) -> None:
        """Invoke the real hook-install failure callback.

        Args:
            pending_key: Sentinel key stored in the pending hook row.
            exc: Exception the bridge would have raised.
        """
        self._on_hook_install_error(pending_key, exc)

    def invoke_on_remove_hook(self) -> None:
        """Invoke the real "Remove Hook" toolbar handler."""
        self._on_remove_hook()

    def invoke_hook_removed(self, hook_id: str) -> None:
        """Invoke the real hook-removed success callback.

        Args:
            hook_id: Identifier of the hook the bridge removed.
        """
        self._on_hook_removed(hook_id)

    def repopulate_hooks(self, hooks: list[HookInfo]) -> None:
        """Drive the real hooks-table repopulation handler.

        Args:
            hooks: Hook records the bridge's ``get_hooks`` would return.
        """
        self._populate_hooks_from_bridge(hooks)

    def invoke_on_run_script_success(self, script_size: int, result: object) -> None:
        """Invoke the real persistent-script success callback.

        Args:
            script_size: Reported script size in characters.
            result: Script handle the bridge returned (possibly unusable).
        """
        self._on_run_script_success(script_size, result)

    def select_hook_row(self, row: int) -> None:
        """Select a hooks-table row as a user click would.

        Args:
            row: Zero-based row index to select.
        """
        self._hooks_table.selectRow(row)

    def hook_ids_snapshot(self) -> list[str]:
        """Return a copy of the panel's parallel hook-id list.

        Returns:
            list[str]: The current ``_hook_ids`` contents, index-aligned with
            the hooks table rows.
        """
        return list(self._hook_ids)

    def hooks_row_count(self) -> int:
        """Return the number of rows in the hooks table.

        Returns:
            int: Current hooks-table row count.
        """
        return self._hooks_table.rowCount()

    def hook_cell_text(self, row: int, column: int) -> str:
        """Return the text of a hooks-table cell.

        Args:
            row: Zero-based row index.
            column: Zero-based column index.

        Returns:
            str: The cell's text, or an empty string when no item is present.
        """
        item = self._hooks_table.item(row, column)
        return item.text() if item is not None else ""

    def console_text(self) -> str:
        """Return the panel console's accumulated text.

        Returns:
            str: Full plain-text console contents.
        """
        return self._console.toPlainText()

    def run_button_enabled(self) -> bool:
        """Return whether the Run button is currently enabled.

        Returns:
            bool: ``True`` when the Run button accepts clicks.
        """
        return self.run_btn.isEnabled()


@pytest.fixture(autouse=True)
def require_frida() -> None:
    """Skip every test in this module when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for Frida panel GUI-audit gate tests")


@pytest.fixture
def draining_dispatch(monkeypatch: pytest.MonkeyPatch) -> Generator[list[Coroutine[object, object, object]]]:
    """Replace ``run_bridge_coroutine_async`` with a synchronous, draining capture.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        list[Coroutine[object, object, object]]: Records every
        dispatched coroutine, in dispatch order.
    """
    captured: list[Coroutine[object, object, object]] = []
    drain_loop = asyncio.new_event_loop()

    def fake_dispatch(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        del parent
        captured.append(coro)
        try:
            result = drain_loop.run_until_complete(coro)
        except _DISPATCH_EXCEPTIONS as exc:
            if on_error is not None:
                on_error(exc)
            return
        if on_success is not None:
            on_success(result)

    monkeypatch.setattr(async_bridge_module, "run_bridge_coroutine_async", fake_dispatch)
    yield captured
    drain_loop.close()


@pytest.fixture
def capturing_dispatch(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Callable[[object], None] | None, Callable[[object], None] | None]]:
    """Replace ``run_bridge_coroutine_async`` with a non-draining capture.

    The dispatched coroutine is closed immediately (never awaited) so no real
    bridge operation runs and no "coroutine was never awaited" warning is
    emitted; the success/error callbacks are recorded so the test can drive
    them in an arbitrary order.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[tuple[Callable[[object], None] | None, Callable[[object], None] | None]]:
        The ``(on_success, on_error)`` callback pair for each dispatch.
    """
    captured: list[tuple[Callable[[object], None] | None, Callable[[object], None] | None]] = []

    def fake_dispatch(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        del parent
        coro.close()
        captured.append((on_success, on_error))

    monkeypatch.setattr(async_bridge_module, "run_bridge_coroutine_async", fake_dispatch)
    return captured


@pytest.mark.usefixtures("qapp")
class TestDeviceSelectionResolvesFromUserData:
    """M6 gates: device switching must use combo userData, not display text."""

    @staticmethod
    def test_usb_selection_connects_usb_not_local(
        draining_dispatch: list[Coroutine[object, object, object]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selecting an enumerated USB device must call ``connect_device('usb', None)``.

        Regression: the pre-fix ``_on_device_changed`` parsed the display string
        ``"USB Device (usb)"`` -- which is neither ``"usb"`` nor
        ``"remote:..."`` -- and therefore dispatched ``connect_device('local',
        None)`` for every enumerated device. This gate populates the combo
        through the real ``_populate_device_combo`` (proving the userData shape
        the production code writes) and asserts the recorded bridge arguments
        are the USB device's real type, not ``"local"``.

        Args:
            draining_dispatch: Captures and drains dispatched coroutines.
            monkeypatch: Pytest monkeypatch fixture.
        """
        recorded: list[tuple[str, str | None]] = []

        async def _record_connect(device_type: str, host: str | None = None) -> FridaDeviceInfo:
            await asyncio.sleep(0)
            recorded.append((device_type, host))
            return FridaDeviceInfo(id=f"connected-{device_type}", name=device_type, device_type=device_type)

        panel = _TestFridaPanel()
        bridge = FridaBridge()
        monkeypatch.setattr(bridge, "connect_device", _record_connect)
        panel.set_bridge(bridge)
        panel.populate_devices(
            [
                FridaDeviceInfo(id="local-id", name="Local System", device_type="local"),
                FridaDeviceInfo(id="usb-serial-9999", name="USB Device", device_type="usb"),
            ],
        )

        panel.select_device_index(1)

        assert len(draining_dispatch) == 1
        assert recorded == [("usb", None)]

    @staticmethod
    def test_remote_selection_extracts_host_from_userdata_id(
        draining_dispatch: list[Coroutine[object, object, object]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selecting an enumerated remote device must forward its type and host.

        Regression: display-text parsing ignored the enumerated remote device
        entirely (``"Remote (remote)"`` matched neither manual branch), so a
        remote selection wrongly connected ``"local"``. This gate asserts the
        resolver reads ``device_type='remote'`` from userData and derives the
        host from the frida ``socket@<host>`` device id.

        Args:
            draining_dispatch: Captures and drains dispatched coroutines.
            monkeypatch: Pytest monkeypatch fixture.
        """
        recorded: list[tuple[str, str | None]] = []

        async def _record_connect(device_type: str, host: str | None = None) -> FridaDeviceInfo:
            await asyncio.sleep(0)
            recorded.append((device_type, host))
            return FridaDeviceInfo(id="connected-remote", name="remote", device_type=device_type)

        panel = _TestFridaPanel()
        bridge = FridaBridge()
        monkeypatch.setattr(bridge, "connect_device", _record_connect)
        panel.set_bridge(bridge)
        panel.populate_devices(
            [
                FridaDeviceInfo(id="local-id", name="Local System", device_type="local"),
                FridaDeviceInfo(id="socket@10.0.0.9:27042", name="Remote", device_type="remote"),
            ],
        )

        panel.select_device_index(1)

        assert len(draining_dispatch) == 1
        assert recorded == [("remote", "10.0.0.9:27042")]

    @staticmethod
    def test_manual_remote_entry_falls_back_to_display_text(
        draining_dispatch: list[Coroutine[object, object, object]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A manual ``remote:<host>`` entry without userData must still resolve.

        Regression guard for the resolver's fallback branch: an item whose
        userData is ``None`` (a manually configured or legacy entry) must be
        parsed from its display text so ``connect_device('remote', host)`` is
        still dispatched with the typed host preserved verbatim.

        Args:
            draining_dispatch: Captures and drains dispatched coroutines.
            monkeypatch: Pytest monkeypatch fixture.
        """
        recorded: list[tuple[str, str | None]] = []

        async def _record_connect(device_type: str, host: str | None = None) -> FridaDeviceInfo:
            await asyncio.sleep(0)
            recorded.append((device_type, host))
            return FridaDeviceInfo(id="connected", name="remote", device_type=device_type)

        panel = _TestFridaPanel()
        bridge = FridaBridge()
        monkeypatch.setattr(bridge, "connect_device", _record_connect)
        panel.set_bridge(bridge)
        panel.seed_device_items(
            [
                ("local", None),
                ("remote:192.168.1.5:27042", None),
            ],
        )

        panel.select_device_index(1)

        assert len(draining_dispatch) == 1
        assert recorded == [("remote", "192.168.1.5:27042")]


@pytest.mark.usefixtures("qapp")
class TestHookCallbacksTrackByStableKey:
    """stale-row gates: async hook callbacks must target rows by hook identity."""

    @staticmethod
    def test_out_of_order_install_callbacks_edit_correct_row(
        capturing_dispatch: list[tuple[Callable[[object], None] | None, Callable[[object], None] | None]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Out-of-order install add/error callbacks must resolve rows by sentinel key.

        Two hooks are queued (rows 0 and 1). Hook A's install *fails* first,
        which removes its pending row and shifts hook B from row 1 to row 0.
        Hook B's install *succeeds* afterwards. With the pre-fix code -- which
        captured the row index at request time and stored a bare ``""`` per
        pending hook -- B's success callback would target the now-nonexistent
        row 1, leave the surviving row stuck on "Installing...", and grow
        ``_hook_ids`` out of sync with the table. This gate asserts the
        surviving row is B, marked Active, with ``_hook_ids`` holding exactly
        B's real id.

        Args:
            capturing_dispatch: Records dispatches without running them.
            monkeypatch: Pytest monkeypatch fixture.
        """
        panel = _TestFridaPanel()
        bridge = FridaBridge()
        panel.set_bridge(bridge)

        monkeypatch.setattr(QInputDialog, "getText", staticmethod(_fixed_get_text("funcA")))
        panel.invoke_on_add_hook()
        monkeypatch.setattr(QInputDialog, "getText", staticmethod(_fixed_get_text("funcB")))
        panel.invoke_on_add_hook()

        assert len(capturing_dispatch) == 2
        keys = panel.hook_ids_snapshot()
        assert len(keys) == 2
        pending_a, pending_b = keys[0], keys[1]
        assert pending_a != pending_b

        panel.invoke_hook_install_error(pending_a, RuntimeError("resolve failed"))
        hook_b = HookInfo(id="hook-B-real", target="funcB", address=0x401000, script_id="script-1", active=True)
        panel.invoke_hook_installed(pending_b, "funcB", hook_b)

        assert panel.hooks_row_count() == 1
        assert panel.hook_ids_snapshot() == ["hook-B-real"]
        assert panel.hook_cell_text(0, _COL_FUNCTION) == "funcB"
        assert panel.hook_cell_text(0, _COL_STATUS) == "Active"
        assert panel.hook_cell_text(0, _COL_ADDRESS) == "0x401000"

    @staticmethod
    def test_removal_callback_targets_hook_id_after_repopulate(
        capturing_dispatch: list[tuple[Callable[[object], None] | None, Callable[[object], None] | None]],
    ) -> None:
        """A hook-removal callback must remove the row whose hook id matches, post-reorder.

        Two active hooks are present. The user removes hook A (row 0); before
        the removal callback returns, a ``get_hooks`` repopulate reorders the
        table so A is now at row 1 and B at row 0. With the pre-fix code -- which
        captured row 0 at request time -- the callback would remove row 0
        (hook B, the wrong hook) and desync ``_hook_ids``. This gate asserts the
        callback locates A by its id and removes it, leaving B intact.

        Args:
            capturing_dispatch: Records dispatches without running them.
        """
        panel = _TestFridaPanel()
        bridge = FridaBridge()
        panel.set_bridge(bridge)
        panel.add_hook_entry("0x401000", "mod", "funcA", "Active", "id-A")
        panel.add_hook_entry("0x402000", "mod", "funcB", "Active", "id-B")

        panel.select_hook_row(0)
        panel.invoke_on_remove_hook()
        assert len(capturing_dispatch) == 1

        panel.repopulate_hooks(
            [
                HookInfo(id="id-B", target="mod!funcB", address=0x402000, script_id="s", active=True),
                HookInfo(id="id-A", target="mod!funcA", address=0x401000, script_id="s", active=True),
            ],
        )
        assert panel.hook_ids_snapshot() == ["id-B", "id-A"]

        panel.invoke_hook_removed("id-A")

        assert panel.hooks_row_count() == 1
        assert panel.hook_ids_snapshot() == ["id-B"]
        assert panel.hook_cell_text(0, _COL_FUNCTION) == "funcB"
        assert panel.hook_cell_text(0, _COL_MODULE) == "mod"


@pytest.mark.usefixtures("qapp")
class TestRunScriptSuccessSurfacesFailure:
    """run-script-raise gate: an unusable handle is surfaced, never raised in the slot."""

    @staticmethod
    def test_unusable_handle_does_not_raise_and_is_surfaced() -> None:
        """An unusable persistent-script handle must be surfaced without raising.

        Regression: the pre-fix ``_on_run_script_success`` reset the UI and then
        executed ``raise RuntimeError`` inside the Qt success slot, so an
        exception escaped the slot after the UI state was already updated. This
        gate calls the real slot with a ``None`` result (an unusable handle) and
        proves it returns normally, re-enables Run, and writes the abort notice
        to the console.
        """
        panel = _TestFridaPanel()
        bridge = FridaBridge()
        panel.set_bridge(bridge)

        panel.invoke_on_run_script_success(128, None)

        assert panel.run_button_enabled() is True
        assert "persistent load aborted" in panel.console_text()

    @staticmethod
    def test_valid_handle_still_disables_run_and_tracks_id() -> None:
        """A valid handle must still take the success path (disable Run, track id).

        Guards that surfacing the failure case did not break the happy path:
        a usable script id disables the Run button (a persistent script is now
        running) and reports the load on the console.
        """
        panel = _TestFridaPanel()
        bridge = FridaBridge()
        panel.set_bridge(bridge)

        panel.invoke_on_run_script_success(64, "persistent-script-id")

        assert panel.run_button_enabled() is False
        assert "Script loaded (persistent)" in panel.console_text()
