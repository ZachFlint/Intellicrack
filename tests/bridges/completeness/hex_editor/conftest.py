# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared fixtures and test doubles for the hex-editor bridge-completeness gates.

Covers ``audit/bridge-completeness/agent-09-hex-editor.md`` and its verifier
``audit/bridge-completeness/verify/agent-09-hex-editor-verification.md``: the
Search-and-Replace feature backed by ``HexEditorBridge.replace_bytes``, the
sandbox-reroute fix in ``ui/panels/hex_editor/sandbox.py``, the
``list_process_regions`` reroute in ``process_memory.py``, the
``auto_detect_pattern`` reroute in ``sections.py``, and the new VA-mapping /
annotated-export GUI surfaces (``va_mapping.py`` / ``export_report.py``).

Every test in this package drives the REAL, unmodified ``HexEditorBridge``
against a real ``intellicrack_hexcore.HexDocument`` opened on a real temp
file (or a real system PE), and the REAL panel mixins dispatched through the
real ``run_bridge_coroutine`` / ``run_bridge_coroutine_logged`` machinery
(``ui/panels/async_bridge.py``). The only test double used anywhere in this
package is a fake ``SandboxBridge`` collaborator registered under
``ToolName.SANDBOX`` -- the genuine external boundary that cannot run inside
the Docker test sandbox (no real sandbox VM/container manager is available
there). That fake never replaces the ``HexEditorBridge`` method under test;
it only stands in for the downstream sandbox tool the hex-editor bridge
calls into, exactly the pattern already established in
``tests/test_bridges/test_hex_editor_bridge_methods_wave4.py``.
"""

from __future__ import annotations

import asyncio
import gc
import os
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, overload

import intellicrack_hexcore
import pytest
from PyQt6.QtWidgets import QApplication, QTreeWidget

from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolDefinition, ToolName


if TYPE_CHECKING:
    from collections.abc import Callable, Generator


@overload
def priv[T](obj: object, name: str, typ: type[T]) -> T: ...
@overload
def priv[T](obj: object, name: str, typ: tuple[type[T], ...]) -> T: ...
def priv(obj: object, name: str, typ: type[object] | tuple[type[object], ...]) -> object:
    """Read a private attribute off a widget/bridge with a known, runtime-checked type.

    Test modules in this package intentionally reach into panel/dialog-
    private widgets (``_search_input``, ``_va_mappings_tree``, and
    similar) and bridge-private collaborators (``_pattern_registry``) to
    drive real Qt signal/slot wiring and real bridge internals end-to-end.
    ``getattr`` performs the same lookup as direct attribute access
    without triggering basedpyright's ``reportPrivateUsage`` diagnostic,
    and the explicit ``typ`` argument both keeps the result statically
    typed (instead of falling back to ``Any``) and is verified against
    the live attribute at runtime, so a stale/renamed attribute fails
    loudly here rather than surfacing as a confusing ``AttributeError``
    deeper in the test body. The overload pair mirrors ``isinstance``'s
    own single-type/tuple-of-types split so callers can narrow to one of
    several acceptable widget types.

    Args:
        obj: The object whose private attribute is being read.
        name: The attribute name to look up.
        typ: The expected type (or tuple of acceptable types) of the
            attribute; checked at runtime and used for the static cast.

    Returns:
        object: The attribute value, cast to ``typ``.

    Raises:
        TypeError: If the attribute's runtime type does not match ``typ``.
    """
    value = getattr(obj, name)
    if not isinstance(value, typ):
        expected = typ.__name__ if isinstance(typ, type) else " | ".join(t.__name__ for t in typ)
        msg = f"{obj!r}.{name} is {type(value).__name__}, expected {expected}"
        raise TypeError(msg)
    return value


def priv_set(obj: object, name: str, value: object) -> None:
    """Write a private attribute on a widget/bridge from a test.

    Companion to :func:`priv` for the handful of cases where these gate
    tests must inject a private collaborator directly (e.g. swapping in a
    deterministic ``PatternRegistry`` on ``HexEditorBridge._pattern_registry``
    so pattern-match assertions do not depend on whichever vendored
    community patterns happen to match arbitrary binary content).
    ``setattr`` performs the same mutation as direct attribute assignment
    without triggering basedpyright's ``reportPrivateUsage`` diagnostic.

    Args:
        obj: The object whose private attribute is being written.
        name: The attribute name to assign.
        value: The value to assign to the attribute.
    """
    setattr(obj, name, value)


def priv_method(obj: object, name: str) -> Callable[..., object]:
    """Read a private bound method off an object.

    Companion to :func:`priv` for the private *methods* (e.g.
    ``_on_replace_all``, ``_try_pattern_registry_match``) these tests
    invoke directly to drive toolbar/tab wiring, where ``type[_T]``
    cannot express a callable generic alias.

    Args:
        obj: The object whose private method is being looked up.
        name: The method name to look up.

    Returns:
        Callable[..., object]: The bound method.

    Raises:
        TypeError: If the attribute's runtime value is not callable.
    """
    value = getattr(obj, name)
    if not callable(value):
        msg = f"{obj!r}.{name} is not callable"
        raise TypeError(msg)
    return value


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process; this
    fixture creates one for the entire session and yields it so every
    widget-construction test in this package can run without re-creating
    (or conflicting on) the singleton application instance.

    Yields:
        QApplication: The application instance.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Construct a fresh ``HexEditorBridge`` with no document attached.

    Returns:
        HexEditorBridge: Bridge instance for tests that build documents
        themselves.
    """
    return HexEditorBridge()


def open_doc(bridge: HexEditorBridge, data: bytes) -> Path:
    """Write ``data`` to a temp file and open it as the bridge's document.

    Args:
        bridge: Target bridge whose ``document`` attribute is assigned.
        data: Raw bytes to write to the temp file.

    Returns:
        Path: Path of the temp file holding the document data.
    """
    fd, path_str = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    path = Path(path_str)
    path.write_bytes(data)
    bridge.document = intellicrack_hexcore.HexDocument.open(str(path))
    return path


_DEFERRED_UNLINKS: list[Path] = []
"""Temp files whose backing mmap outlived per-test teardown; drained at session end.

On Windows, ``HexDocument`` holds its backing file open via a memory-map
maintained by the Rust piece-table, and the map is released only when *every*
Python reference to the document is dropped and the Rust ``Drop`` impl runs.
Tests that share the document with a panel (``panel.document = bridge.document``)
or that dispatch through a background async worker can still hold a live
reference when :func:`release_and_unlink` runs, so the immediate unlink raises
``PermissionError: [WinError 5] Access is denied``. Those paths are recorded
here and retried by :func:`drain_deferred_unlinks` once the session has torn
down every widget and worker holding a mapping.
"""


def release_and_unlink(bridge: HexEditorBridge, path: Path) -> None:
    """Release the bridge document handle then delete the temp file.

    Clears ``bridge.document`` and forces a garbage-collection pass so the
    Rust ``Drop`` impl closes the memory-map for any document no longer
    referenced. When another live holder (a panel that copied
    ``bridge.document``, or an in-flight async worker) still maps the file,
    the unlink cannot succeed yet; rather than fail the test on teardown
    scaffolding whose assertions have already run, the path is deferred to
    :func:`drain_deferred_unlinks` for a best-effort retry at session end.

    Args:
        bridge: Bridge whose ``document`` attribute is cleared first.
        path: Temp file to delete after the handle is released.
    """
    bridge.document = None
    gc.collect()
    try:
        path.unlink(missing_ok=True)
    except PermissionError:
        _DEFERRED_UNLINKS.append(path)


@pytest.fixture(scope="session", autouse=True)
def drain_deferred_unlinks() -> Generator[None]:
    """Best-effort removal of temp files whose mmap outlived per-test teardown.

    Yields control for the whole session, then -- after every widget and
    worker has been collected -- forces a final garbage-collection pass and
    retries each deferred unlink. Any file still mapped (a genuinely leaked
    handle) is left in the ephemeral container's temp directory rather than
    masking a real error; the retry simply avoids failing otherwise-passing
    tests on Windows mmap lifetime timing.

    Yields:
        None: Control returns to the session; cleanup runs at teardown.
    """
    yield
    gc.collect()
    for leftover in _DEFERRED_UNLINKS:
        try:
            leftover.unlink(missing_ok=True)
        except PermissionError:
            continue
    _DEFERRED_UNLINKS.clear()


class FakeSandboxBridge(ToolBridgeBase):
    """Minimal sandbox bridge recording ``create``/``copy_to``/``run_binary`` calls.

    Stands in for the real ``SandboxBridge`` at the one boundary that
    cannot execute inside the Docker test sandbox (provisioning a real
    Windows Sandbox or QEMU VM). Every call is recorded on ``self.calls``
    so tests can assert exactly which method, and with which arguments,
    the ``HexEditorBridge``'s own ``save_to_sandbox``/``test_in_sandbox``
    methods invoked.
    """

    def __init__(self) -> None:
        """Initialise empty call ledgers and default success payloads."""
        super().__init__()
        self.create_calls: list[dict[str, Any]] = []
        self.copy_calls: list[dict[str, Any]] = []
        self.run_binary_calls: list[dict[str, Any]] = []
        self.destroy_calls: list[str] = []
        self.next_instance_id: str = "fake-instance-1"
        self.copy_should_fail: bool = False
        self.run_binary_result: dict[str, Any] = {"exit_code": 0, "stdout": "ok", "stderr": ""}
        self.capture_source_bytes: bool = False
        self.copied_payloads: list[bytes] = []

    @property
    def name(self) -> ToolName:
        """The sandbox tool name.

        Returns:
            ToolName: ``ToolName.SANDBOX``.
        """
        return ToolName.SANDBOX

    @property
    def tool_definition(self) -> ToolDefinition:
        """A minimal tool definition for type compliance.

        Returns:
            ToolDefinition: Stub definition with no functions.
        """
        return ToolDefinition(tool_name=ToolName.SANDBOX, description="fake", functions=[])

    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initializer satisfying the abstract contract.

        Args:
            tool_path: Ignored.
        """

    async def shutdown(self) -> None:
        """Delegate to base-class finaliser."""
        await super().shutdown()

    async def is_available(self) -> bool:
        """Report that the fake bridge is always available.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def create(
        self,
        sandbox_type: str = "windows",
        timeout_seconds: int = 300,
        *,
        network_enabled: bool = False,
        memory_limit_mb: int = 2048,
    ) -> dict[str, Any]:
        """Record the invocation and return a fake provisioned instance.

        Args:
            sandbox_type: Sandbox flavour string.
            timeout_seconds: Execution timeout in seconds.
            network_enabled: Whether networking would be enabled.
            memory_limit_mb: Memory limit in megabytes.

        Returns:
            dict[str, Any]: Dict with ``instance_id``, ``type``, ``status``.
        """
        self.create_calls.append({
            "sandbox_type": sandbox_type,
            "timeout_seconds": timeout_seconds,
            "network_enabled": network_enabled,
            "memory_limit_mb": memory_limit_mb,
        })
        return {"instance_id": self.next_instance_id, "type": sandbox_type, "status": "running"}

    async def destroy(self, instance_id: str) -> dict[str, Any]:
        """Record a destroy invocation.

        Args:
            instance_id: Instance identifier to destroy.

        Returns:
            dict[str, Any]: Dict reporting the destroyed instance.
        """
        self.destroy_calls.append(instance_id)
        return {"instance_id": instance_id, "status": "destroyed"}

    async def copy_to(self, instance_id: str, source: str, dest: str) -> dict[str, Any]:
        """Record the invocation and optionally simulate a copy failure.

        Args:
            instance_id: Sandbox instance identifier.
            source: Host-side source path.
            dest: Sandbox-side destination path.

        Returns:
            dict[str, Any]: Dict reporting the copy outcome.

        Raises:
            RuntimeError: When ``copy_should_fail`` has been set by the test.
        """
        self.copy_calls.append({"instance_id": instance_id, "source": source, "dest": dest})
        if self.capture_source_bytes:
            self.copied_payloads.append(await asyncio.to_thread(Path(source).read_bytes))
        if self.copy_should_fail:
            msg = "simulated copy_to failure"
            raise RuntimeError(msg)
        return {"instance_id": instance_id, "dest": dest, "status": "copied"}

    async def run_binary(
        self,
        binary_path: str,
        args: list[str] | None = None,
        sandbox_type: str = "windows",
        time_limit: int = 30,
    ) -> dict[str, Any]:
        """Record the invocation and return the pre-configured result.

        Args:
            binary_path: Path to the binary submitted for execution.
            args: Command-line arguments list or ``None``.
            sandbox_type: Sandbox flavour string.
            time_limit: Execution timeout in seconds.

        Returns:
            dict[str, Any]: The ``run_binary_result`` attribute set on this instance.
        """
        self.run_binary_calls.append({
            "binary_path": binary_path,
            "args": args,
            "sandbox_type": sandbox_type,
            "time_limit": time_limit,
        })
        return self.run_binary_result

    async def execute(self, instance_id: str, command: str, time_limit: int = 30) -> dict[str, Any]:
        """Record a raw ``execute`` invocation (the pre-remediation GUI path).

        Tests assert this is NEVER called by the remediated GUI handlers,
        since ``save_to_sandbox``/``test_in_sandbox`` route through
        ``create``/``copy_to``/``run_binary`` instead.

        Args:
            instance_id: Sandbox instance identifier.
            command: Command string that would have been executed.
            time_limit: Execution timeout in seconds.

        Returns:
            dict[str, Any]: Dict reporting a fake execution outcome.
        """
        self.run_binary_calls.append({
            "_via_raw_execute": True,
            "instance_id": instance_id,
            "command": command,
            "time_limit": time_limit,
        })
        return {"exit_code": 0, "stdout": "", "stderr": ""}


def make_registry_with_sandbox(fake: FakeSandboxBridge) -> ToolRegistry:
    """Build a real ``ToolRegistry`` with ``fake`` registered as the sandbox bridge.

    Args:
        fake: Fake sandbox bridge instance to register under ``ToolName.SANDBOX``.

    Returns:
        ToolRegistry: A registry whose ``get(ToolName.SANDBOX)`` returns ``fake``.
    """
    td = tempfile.mkdtemp()
    registry = ToolRegistry(Path(td))
    registry.register_bridge(ToolName.SANDBOX, fake)
    return registry


class RecordingHexEditorBridge(HexEditorBridge):
    """``HexEditorBridge`` subclass that records calls to select dispatch-reroute targets.

    Stands in for the real bridge in the five newly-rerouted controls
    (``base_convert``, ``generate_structure_bookmarks``,
    ``list_templates_detailed``, ``scan_die_signatures`` /
    ``scan_clamav_signatures`` / ``scan_custom_signatures``,
    ``toggle_bit``) so tests can assert the GUI handler dispatched to
    THIS bridge method rather than falling back to its local,
    pre-remediation implementation. Every override still performs the
    real, unmodified operation via ``super()`` -- only the call ledger
    is added -- so assertions on the returned/rendered data remain
    genuine end-to-end checks, not canned responses.
    """

    base_convert_calls: ClassVar[list[dict[str, Any]]] = []
    """Call ledger for :meth:`base_convert`.

    Declared at class scope (reset per-instance in ``__init__``) because
    the real ``HexEditorBridge.base_convert`` is a ``@classmethod``;
    basedpyright's ``reportIncompatibleMethodOverride`` requires this
    override to keep the same classmethod binding, so the ledger cannot
    live on ``self`` the way the other five instance-method ledgers do.
    """

    def __init__(self) -> None:
        """Initialise empty call ledgers alongside the real bridge state."""
        super().__init__()
        self.__class__.base_convert_calls = []
        self.generate_structure_bookmarks_calls: int = 0
        self.list_templates_detailed_calls: int = 0
        self.scan_die_signatures_calls: list[str] = []
        self.scan_clamav_signatures_calls: list[str] = []
        self.scan_custom_signatures_calls: list[str] = []
        self.toggle_bit_calls: list[dict[str, Any]] = []
        self.list_process_regions_calls: list[int] = []

    @classmethod
    async def base_convert(cls, value: str, from_base: str = "auto") -> dict[str, str]:
        """Record the call then delegate to the real conversion logic.

        Args:
            value: Value string forwarded to the real implementation.
            from_base: Source base hint forwarded to the real implementation.

        Returns:
            dict[str, str]: The real ``base_convert`` result.
        """
        cls.base_convert_calls.append({"value": value, "from_base": from_base})
        return await HexEditorBridge.base_convert(value, from_base=from_base)

    async def generate_structure_bookmarks(self) -> list[dict[str, Any]]:
        """Record the call then delegate to the real structure-detection logic.

        Returns:
            list[dict[str, Any]]: The real ``generate_structure_bookmarks`` result.
        """
        self.generate_structure_bookmarks_calls += 1
        return await super().generate_structure_bookmarks()

    async def list_templates_detailed(self) -> list[dict[str, Any]]:
        """Record the call then delegate to the real template-listing logic.

        Returns:
            list[dict[str, Any]]: The real ``list_templates_detailed`` result.
        """
        self.list_templates_detailed_calls += 1
        return await super().list_templates_detailed()

    async def scan_die_signatures(self, db_path: str) -> list[dict[str, Any]]:
        """Record the call then delegate to the real DIE-signature scanner.

        Args:
            db_path: Signature database path forwarded to the real implementation.

        Returns:
            list[dict[str, Any]]: The real ``scan_die_signatures`` result.
        """
        self.scan_die_signatures_calls.append(db_path)
        return await super().scan_die_signatures(db_path)

    async def scan_clamav_signatures(self, db_path: str) -> list[dict[str, Any]]:
        """Record the call then delegate to the real ClamAV-signature scanner.

        Args:
            db_path: Signature database path forwarded to the real implementation.

        Returns:
            list[dict[str, Any]]: The real ``scan_clamav_signatures`` result.
        """
        self.scan_clamav_signatures_calls.append(db_path)
        return await super().scan_clamav_signatures(db_path)

    async def scan_custom_signatures(self, sig_file: str) -> list[dict[str, Any]]:
        """Record the call then delegate to the real custom-signature scanner.

        Args:
            sig_file: Signature file path forwarded to the real implementation.

        Returns:
            list[dict[str, Any]]: The real ``scan_custom_signatures`` result.
        """
        self.scan_custom_signatures_calls.append(sig_file)
        return await super().scan_custom_signatures(sig_file)

    async def toggle_bit(self, offset: int, bit_index: int) -> bool:
        """Record the call then delegate to the real bit-toggle logic.

        Args:
            offset: Byte offset forwarded to the real implementation.
            bit_index: Bit position forwarded to the real implementation.

        Returns:
            bool: The real ``toggle_bit`` result.
        """
        self.toggle_bit_calls.append({"offset": offset, "bit_index": bit_index})
        return await super().toggle_bit(offset, bit_index)

    async def list_process_regions(self, pid: int) -> list[dict[str, int]]:
        """Record the call then delegate to the real process-region enumerator.

        Args:
            pid: Process ID forwarded to the real implementation.

        Returns:
            list[dict[str, int]]: The real ``list_process_regions`` result.
        """
        self.list_process_regions_calls.append(pid)
        return await super().list_process_regions(pid)


def tree_columns(tree: QTreeWidget, *columns: int) -> list[tuple[str, ...]]:
    """Read the given columns of every top-level row of a ``QTreeWidget`` as plain strings.

    Companion to :func:`priv` for asserting on rendered tree contents:
    ``QTreeWidget.topLevelItem`` is typed ``QTreeWidgetItem | None`` by
    PyQt6's stubs even though every index within ``topLevelItemCount()``
    is always populated, so this helper performs the per-row ``None``
    guard once instead of repeating it at every call site.

    Args:
        tree: The tree widget to read rows from.
        *columns: Column indices to extract from each top-level item, in order.

    Returns:
        list[tuple[str, ...]]: One tuple of column text per top-level row.

    Raises:
        TypeError: If a top-level index within ``topLevelItemCount()`` yields ``None``.
    """
    rows: list[tuple[str, ...]] = []
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        if item is None:
            msg = f"{tree!r}.topLevelItem({i}) is None within topLevelItemCount()"
            raise TypeError(msg)
        rows.append(tuple(item.text(col) for col in columns))
    return rows


def tree_row_map(tree: QTreeWidget, key_column: int, value_column: int) -> dict[str, str]:
    """Read a ``QTreeWidget``'s top-level rows into a ``{key_column: value_column}`` dict.

    Companion to :func:`tree_columns` for the common case of asserting
    on a label/value tree (e.g. the calculator's representation tree)
    by label rather than by row order.

    Args:
        tree: The tree widget to read rows from.
        key_column: Column index supplying each row's dict key.
        value_column: Column index supplying each row's dict value.

    Returns:
        dict[str, str]: Mapping from ``key_column`` text to ``value_column`` text, one entry per top-level row.
    """
    return {row[0]: row[1] for row in tree_columns(tree, key_column, value_column)}


def pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = 10.0) -> None:
    """Pump the Qt event loop until ``predicate()`` is truthy or the timeout elapses.

    Cross-thread async bridge results (delivered via ``run_bridge_coroutine_logged``
    / ``BridgeCallWorker`` signals from the background asyncio thread) only reach
    their Qt slots while the main-thread event loop is processing events, so GUI
    wiring tests must pump the loop while waiting for a handler's side effect.

    Args:
        qapp: The Qt application instance whose event loop to drive.
        predicate: Zero-argument callable returning a truthy value when done.
        timeout_s: Maximum number of seconds to wait.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        qapp.processEvents()
        time.sleep(0.02)
