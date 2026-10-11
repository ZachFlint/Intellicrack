# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the installer, status checker and settings dialogs in ``intellicrack.ui.tool_config``.

Every test drives real objects. The installer worker is run against real loopback HTTP servers: a fixed-body server that sends a
``Content-Length``, a route-scripted server that answers chunked, and a closed loopback port that refuses connections. Archives are built with
:mod:`zipfile` and extracted into ``tmp_path``. The status checker is pointed at directory layouts created on disk, the settings widgets and
dialogs read and write a real ``tools.json`` below a per-test state directory, and the status dialog is refreshed through its real worker
threads. The workers' ``run`` bodies are called on the test thread because the coverage tracer does not see code that runs on a ``QThread``.
Expected values come from the documented behavior of each step: progress percentages from the arithmetic of the download chunking, messages
from the user-facing contract, file contents from what the product is documented to write.
"""

from __future__ import annotations

import ast
import io
import json
import platform
import runpy
import socket
import zipfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Protocol, cast, override

import pytest
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
)

from intellicrack.bridges import installer as installer_module
from intellicrack.ui.resources import IconManager
from intellicrack.ui.tool_config import (
    ToolCapabilitiesWidget,
    ToolConfigDialog,
    ToolInstallWorker,
    ToolSettingsWidget,
    ToolStatusCheckWorker,
    ToolStatusDialog,
    ToolStatusEntry,
)
from tests._helpers.scripted_http_server import (
    ScriptedHttpServer as RouteServer,
    ScriptedResponse,
    json_response,
)
from tests._helpers.stalling_http import ScriptedHttpServer as FixedBodyServer
from tests.ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtCore import pyqtBoundSignal
    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_CHUNK_BYTES: int = 8192
_WAIT_MS: int = 30_000
_JOIN_MS: int = 15_000
_TOOL_IDS: tuple[str, ...] = ("ghidra", "x64dbg", "frida", "cutter", "process", "binary")
_DISPLAY_NAMES: tuple[str, ...] = ("Ghidra", "x64dbg", "Frida", "Cutter", "Process Control", "Binary Operations")
_PROXY_VARIABLES: tuple[str, ...] = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
_BUILTIN_STATUS: str = "Available (built-in)"
_API_PATH: str = "/repos/demo/releases/latest"

_GHIDRA_FOUND_LAYOUTS: list[tuple[str, ...]] = [
    ("ghidra_11.2/support/analyzeHeadless.bat",),
    ("ghidra_11.2/support/analyzeHeadless",),
    ("support/analyzeHeadless.bat",),
    ("support/analyzeHeadless",),
    ("ghidra_11.2/readme.txt", "support/analyzeHeadless.bat"),
    ("docs/readme.txt", "ghidra_11.2/support/analyzeHeadless.bat"),
]
_GHIDRA_FOUND_IDS: list[str] = [
    "versioned-dir-bat",
    "versioned-dir-plain",
    "root-bat",
    "root-plain",
    "versioned-dir-without-script-falls-back-to-root",
    "skips-unrelated-directory",
]
_GHIDRA_MISSING_LAYOUTS: list[tuple[str, ...]] = [
    (),
    ("docs/readme.txt", "top.txt"),
    ("ghidra_11.2/readme.txt",),
]
_GHIDRA_MISSING_IDS: list[str] = ["empty-root", "unrelated-entries-only", "versioned-dir-without-script"]
_X64DBG_LAYOUTS: list[str] = [
    "release/x64/x64dbg.exe",
    "release/x32/x32dbg.exe",
    "x64/x64dbg.exe",
    "x64dbg.exe",
]


@dataclass(frozen=True)
class _Outcome:
    """Signals recorded while an install worker ran.

    Attributes:
        progress: Every percentage emitted through ``progress``, in order.
        finished: Every ``(success, message)`` pair emitted through ``install_finished``, in order.
    """

    progress: list[int]
    finished: list[tuple[bool, str]]


class _ByteSink(Protocol):
    """The part of a response stream a body writer uses."""

    def write(self, data: bytes, /) -> int:
        """Write bytes.

        Args:
            data: The bytes to write.

        Returns:
            int: How many bytes were written.
        """
        ...

    def flush(self) -> None:
        """Flush buffered bytes."""
        ...


class _TruncatingServer(FixedBodyServer):
    """Fixed-body server that announces the whole body but sends only its first half before closing."""

    @override
    def write_body(self, stream: _ByteSink) -> None:
        """Write half of the scripted body and stop.

        Args:
            stream: The response stream.
        """
        _ = stream.write(self.body[: len(self.body) // 2])


def _attr[T](obj: object, name: str, kind: type[T]) -> T:
    """Read a private attribute and narrow it to its expected type.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        kind: Type the attribute must have.

    Returns:
        T: The attribute value.
    """
    value: object = getattr(obj, name)
    assert isinstance(value, kind)
    return value


def _call(obj: object, name: str, *args: object, **kwargs: object) -> object:
    """Call a private method by name.

    Args:
        obj: Object (or class) that owns the method.
        name: Method name.
        *args: Positional arguments for the method.
        **kwargs: Keyword arguments for the method.

    Returns:
        object: Whatever the method returned.
    """
    method: object = getattr(obj, name)
    return cast("Callable[..., object]", method)(*args, **kwargs)


def _record(signal: pyqtBoundSignal) -> SignalRecorder:
    """Connect a recorder to a signal.

    Args:
        signal: The bound signal to observe.

    Returns:
        SignalRecorder: Recorder that stores the arguments of each emission.
    """
    recorder = SignalRecorder()
    _ = signal.connect(recorder)
    return recorder


def _capture_dialog(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    answer: QMessageBox.StandardButton = QMessageBox.StandardButton.Ok,
) -> list[tuple[str, str]]:
    """Replace one ``QMessageBox`` static function with a recorder that answers without a modal.

    Args:
        monkeypatch: Fixture that undoes the replacement.
        name: Name of the static function, such as ``"warning"``.
        answer: Button the replacement reports as pressed.

    Returns:
        list[tuple[str, str]]: ``(title, text)`` of every call, appended as the calls happen.
    """
    captured: list[tuple[str, str]] = []

    def _replacement(_parent: object, title: str, text: str, *_rest: object) -> QMessageBox.StandardButton:
        """Record the dialog request and answer it.

        Args:
            _parent: Parent widget passed by the caller.
            title: Dialog title.
            text: Dialog body.
            *_rest: Remaining positional arguments, such as the button set.

        Returns:
            QMessageBox.StandardButton: The configured answer.
        """
        captured.append((title, text))
        return answer

    monkeypatch.setattr(QMessageBox, name, _replacement)
    return captured


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    """Build an uncompressed ZIP archive in memory.

    Args:
        members: Archive member names mapped to their contents.

    Returns:
        bytes: The archive.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for member_name, data in members.items():
            archive.writestr(member_name, data)
    return buffer.getvalue()


def _closed_port() -> int:
    """Find a loopback TCP port nothing is listening on.

    Returns:
        int: A port that refuses connections.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _download_progress(total: int) -> list[int]:
    """Compute the progress percentages a download of ``total`` bytes reports.

    The download phase maps the fraction received onto the 10 to 80 percent band, once per 8192-byte chunk.

    Args:
        total: Size of the downloaded body in bytes.

    Returns:
        list[int]: One percentage per chunk, in order.
    """
    chunk_count = -(-total // _CHUNK_BYTES)
    return [int(10 + (min(index * _CHUNK_BYTES, total) / total) * 70) for index in range(1, chunk_count + 1)]


def _worker_class(urls: dict[str, dict[str, str]]) -> type[ToolInstallWorker]:
    """Build an installer subclass whose download table points at test servers.

    Args:
        urls: Tool id mapped to its download entry.

    Returns:
        type[ToolInstallWorker]: Subclass of the real installer using ``urls``.
    """

    class _ConfiguredInstallWorker(ToolInstallWorker):
        """Real installer worker with a test download table."""

        DOWNLOAD_URLS: ClassVar[dict[str, dict[str, str]]] = urls

    return _ConfiguredInstallWorker


def _run_install(worker: ToolInstallWorker) -> _Outcome:
    """Run an install worker on the calling thread and collect its signals.

    Args:
        worker: The worker to run.

    Returns:
        _Outcome: Progress percentages and finished messages in emission order.
    """
    progress = _record(worker.progress)
    finished = _record(worker.install_finished)
    worker.run()
    return _Outcome(
        progress=[int(call[0]) for call in progress.calls],
        finished=[(bool(call[0]), str(call[1])) for call in finished.calls],
    )


def _run_status(tool_id: str, tool_path: str) -> tuple[str, bool, str]:
    """Run a status-check worker on the calling thread and return its single result.

    Args:
        tool_id: Tool identifier to check.
        tool_path: Configured tool path.

    Returns:
        tuple[str, bool, str]: The emitted ``(tool_id, available, message)``.
    """
    worker = ToolStatusCheckWorker(tool_id, tool_path)
    recorder = _record(worker.status_checked)
    worker.run()
    assert recorder.times_called == 1
    emitted_id, available, message = recorder.calls[0]
    return str(emitted_id), bool(available), str(message)


def _make_layout(root: Path, layout: tuple[str, ...]) -> None:
    """Create files (and their parent directories) below ``root``.

    Args:
        root: Directory to populate.
        layout: Relative file paths using forward slashes.
    """
    root.mkdir(parents=True, exist_ok=True)
    for relative in layout:
        target = root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"x")


def _row_texts(widget: QListWidget) -> list[str]:
    """Return the text of every row of a list widget.

    Args:
        widget: The list widget.

    Returns:
        list[str]: Row texts in display order.
    """
    texts: list[str] = []
    for row in range(widget.count()):
        item = widget.item(row)
        assert item is not None
        texts.append(item.text())
    return texts


def _write_tool_settings(config_dir: Path, settings: dict[str, dict[str, object]]) -> Path:
    """Write a ``tools.json`` file into a configuration directory.

    Args:
        config_dir: Directory to hold the file; created when missing.
        settings: Tool id mapped to its stored settings.

    Returns:
        Path: The written file.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "tools.json"
    config_file.write_text(json.dumps(settings), encoding="utf-8")
    return config_file


def _make_widget(
    qtbot: QtBot,
    tmp_path: Path,
    tool_id: str = "ghidra",
    display_name: str = "Ghidra",
    *,
    config_path: Path | None = None,
) -> ToolSettingsWidget:
    """Build a settings widget rooted below ``tmp_path`` and register it for cleanup.

    Args:
        qtbot: pytest-qt bot used to close the widget at teardown.
        tmp_path: Directory holding the tools directory and the default config file.
        tool_id: Tool identifier.
        display_name: Human-readable tool name.
        config_path: Config file to use; defaults to ``tmp_path / "tools.json"``.

    Returns:
        ToolSettingsWidget: The live widget.
    """
    widget = ToolSettingsWidget(
        tool_id,
        display_name,
        "Test tool",
        tmp_path / "tools",
        config_path=config_path or tmp_path / "tools.json",
    )
    qtbot.addWidget(widget)
    return widget


def _make_status_dialog(qtbot: QtBot, statuses: dict[str, ToolStatusEntry]) -> ToolStatusDialog:
    """Build a status dialog from a pre-fetched snapshot, so no worker is started.

    Args:
        qtbot: pytest-qt bot used to close the dialog at teardown.
        statuses: Pre-fetched status entries by tool id.

    Returns:
        ToolStatusDialog: The live dialog.
    """
    dialog = ToolStatusDialog(tool_statuses=statuses)
    qtbot.addWidget(dialog)
    return dialog


def _prefetched(omit: str | None = None) -> dict[str, ToolStatusEntry]:
    """Build a complete pre-fetched status snapshot.

    Args:
        omit: Tool id to leave out of the snapshot.

    Returns:
        dict[str, ToolStatusEntry]: Entries for every tool except ``omit``.
    """
    entries: dict[str, ToolStatusEntry] = {
        "ghidra": {"available": True, "path": None, "message": "Ghidra installed"},
        "x64dbg": {"available": False, "path": None, "message": "x64dbg.exe not found"},
        "frida": {"available": True, "path": None, "message": "Frida 1.0 available"},
        "cutter": {"available": False, "path": None, "message": "Cutter executable not found"},
        "process": {"available": True, "path": None, "message": _BUILTIN_STATUS},
        "binary": {"available": True, "path": None, "message": _BUILTIN_STATUS},
    }
    if omit is not None:
        del entries[omit]
    return entries


def _refresh_and_collect(qtbot: QtBot, dialog: ToolStatusDialog) -> list[str]:
    """Wait for a dialog's running status workers, join them and return the rendered rows.

    Args:
        qtbot: pytest-qt bot used to wait while Qt delivers the workers' results.
        dialog: Dialog whose workers were just started.

    Returns:
        list[str]: Row texts once every tool reported.
    """
    workers = list(cast("list[ToolStatusCheckWorker]", getattr(dialog, "_status_workers")))
    refresh = _attr(dialog, "_refresh_btn", QPushButton)
    qtbot.waitUntil(refresh.isEnabled, timeout=_WAIT_MS)
    for worker in workers:
        assert worker.wait(_JOIN_MS)
    return _row_texts(_attr(dialog, "_status_list", QListWidget))


@pytest.fixture
def direct_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make HTTP clients in this test connect straight to loopback, ignoring any proxy settings.

    Args:
        monkeypatch: Fixture that restores the environment.
    """
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


@pytest.fixture
def dead_proxy(monkeypatch: pytest.MonkeyPatch) -> str:
    """Route every HTTP client in this test through a loopback proxy port that refuses connections.

    Nothing leaves the machine: any request, whatever its destination, fails at the first hop.

    Args:
        monkeypatch: Fixture that restores the environment.

    Returns:
        str: URL of the unreachable proxy.
    """
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    proxy_url = f"http://127.0.0.1:{_closed_port()}"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, proxy_url)
    return proxy_url


@pytest.fixture
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the writable state root, and so ``tools.json``, below ``tmp_path``.

    The state directory is only honored when it sits inside the user profile, so the profile variable is pointed at ``tmp_path`` too.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the environment.

    Returns:
        Path: The configuration directory that will hold ``tools.json``.
    """
    home = tmp_path / "home"
    state = home / "state"
    state.mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("INTELLICRACK_STATE_DIR", str(state))
    return state.resolve() / ".intellicrack"


@pytest.fixture
def empty_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``PATH`` at an empty directory so no tool named on the command line can be found.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the environment.

    Returns:
        Path: The empty directory now serving as ``PATH``.
    """
    bin_dir = tmp_path / "emptybin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir))
    return bin_dir


@pytest.fixture
def offline_pip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any pip run by the product refuse to use an index or to check for a new pip release.

    Args:
        monkeypatch: Fixture that restores the environment.
    """
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    monkeypatch.setenv("PIP_DISABLE_PIP_VERSION_CHECK", "1")


def _install_ghidra_bridge_files(tmp_path: Path) -> Path:
    """Run the Ghidra post-install step against a versioned Ghidra directory.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: The Ghidra root the step populated.
    """
    install_path = tmp_path / "ghidra"
    root = install_path / "ghidra_11.2.1_PUBLIC"
    root.mkdir(parents=True)
    _ = _call(ToolInstallWorker("ghidra", install_path), "_post_install_ghidra")
    return root


@pytest.mark.usefixtures("direct_network")
def test_unknown_tool_install_reports_missing_download_url(tmp_path: Path) -> None:
    """A tool without a download entry fails at once and creates nothing.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "frida"

    outcome = _run_install(ToolInstallWorker("frida", install_path))

    assert outcome.finished == [(False, "No download URL for frida")]
    assert outcome.progress == []
    assert not install_path.exists()


@pytest.mark.usefixtures("direct_network")
def test_direct_url_install_downloads_extracts_and_reports_progress(tmp_path: Path) -> None:
    """A direct-URL tool downloads, extracts and reports each stage with the chunk-derived percentages.

    Args:
        tmp_path: Per-test temporary directory.
    """
    payload = b"hello" * 4000
    body = _zip_bytes({"demo/readme.txt": payload})
    install_path = tmp_path / "install"
    with FixedBodyServer(status=200, body=body) as server:
        worker_class = _worker_class({"demo": {"url": server.url, "name": "Demo Tool"}})
        outcome = _run_install(worker_class("demo", install_path))
        request_count = server.requests

    assert request_count == 1
    assert outcome.finished == [(True, "Demo Tool installed successfully")]
    assert outcome.progress == [3, 5, 10, *_download_progress(len(body)), 85, 95, 100]
    assert (install_path / "demo" / "readme.txt").read_bytes() == payload


@pytest.mark.usefixtures("direct_network")
def test_chunked_download_without_length_reports_no_download_progress(tmp_path: Path) -> None:
    """Without a ``Content-Length`` the download phase reports nothing, but the install still completes.

    Args:
        tmp_path: Per-test temporary directory.
    """
    payload = b"world" * 100
    body = _zip_bytes({"demo/data.bin": payload})
    install_path = tmp_path / "install"
    with RouteServer() as server:
        server.script("GET", "/demo.zip", ScriptedResponse(headers=(("content-type", "application/zip"),), chunks=(body,)))
        worker_class = _worker_class({"demo": {"url": f"{server.origin}/demo.zip", "name": "Demo Tool"}})
        outcome = _run_install(worker_class("demo", install_path))

    assert outcome.progress == [3, 5, 10, 85, 95, 100]
    assert outcome.finished == [(True, "Demo Tool installed successfully")]
    assert (install_path / "demo" / "data.bin").read_bytes() == payload


@pytest.mark.usefixtures("direct_network")
def test_stream_download_returns_counts_and_writes_file(tmp_path: Path) -> None:
    """The download step returns the bytes received and the announced size, and writes the body to disk.

    Args:
        tmp_path: Per-test temporary directory.
    """
    body = bytes(range(256)) * 80
    destination = tmp_path / "download.bin"
    with FixedBodyServer(status=200, body=body) as server:
        worker = ToolInstallWorker("demo", tmp_path / "install")
        result = cast("tuple[int, int] | None", _call(worker, "_stream_download", server.url, destination))

    assert result == (len(body), len(body))
    assert destination.read_bytes() == body


@pytest.mark.usefixtures("direct_network")
def test_stream_download_reports_zero_total_for_chunked_response(tmp_path: Path) -> None:
    """A chunked response has no announced size, so the total is reported as zero.

    Args:
        tmp_path: Per-test temporary directory.
    """
    body = b"chunked-body" * 50
    destination = tmp_path / "download.bin"
    with RouteServer() as server:
        server.script("GET", "/blob", ScriptedResponse(chunks=(body,)))
        worker = ToolInstallWorker("demo", tmp_path / "install")
        result = cast("tuple[int, int] | None", _call(worker, "_stream_download", f"{server.origin}/blob", destination))

    assert result == (len(body), 0)
    assert destination.read_bytes() == body


@pytest.mark.usefixtures("direct_network")
def test_install_reports_http_error_status_and_stops(tmp_path: Path) -> None:
    """A non-200 download response fails the install with the status code and extracts nothing.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "install"
    with FixedBodyServer(status=500, body=b"upstream failure") as server:
        worker_class = _worker_class({"demo": {"url": server.url, "name": "Demo Tool"}})
        outcome = _run_install(worker_class("demo", install_path))

    assert outcome.finished == [(False, "Download failed: HTTP 500")]
    assert outcome.progress == [3, 5, 10]
    assert list(install_path.iterdir()) == []


@pytest.mark.usefixtures("direct_network")
def test_install_rejects_download_that_is_not_a_zip_archive(tmp_path: Path) -> None:
    """A download that is not a ZIP archive fails the install before post-install work.

    Args:
        tmp_path: Per-test temporary directory.
    """
    body = b"this is not a zip archive"
    install_path = tmp_path / "install"
    with FixedBodyServer(status=200, body=body) as server:
        worker_class = _worker_class({"demo": {"url": server.url, "name": "Demo Tool"}})
        outcome = _run_install(worker_class("demo", install_path))

    assert outcome.finished == [(False, "Downloaded file is not a valid ZIP archive")]
    assert outcome.progress == [3, 5, 10, *_download_progress(len(body)), 85]


@pytest.mark.usefixtures("direct_network")
def test_install_reports_connection_refused(tmp_path: Path) -> None:
    """A download server that refuses connections is reported as unreachable.

    Args:
        tmp_path: Per-test temporary directory.
    """
    url = f"http://127.0.0.1:{_closed_port()}/demo.zip"
    worker_class = _worker_class({"demo": {"url": url, "name": "Demo Tool"}})

    outcome = _run_install(worker_class("demo", tmp_path / "install"))

    assert outcome.finished == [(False, "Could not connect to download server")]
    assert outcome.progress == [3, 5, 10]


@pytest.mark.usefixtures("direct_network")
def test_install_reports_body_cut_short_as_download_failure(tmp_path: Path) -> None:
    """A server that closes before sending the announced body fails the install with a download error.

    Args:
        tmp_path: Per-test temporary directory.
    """
    with _TruncatingServer(status=200, body=b"x" * 6000) as server:
        worker_class = _worker_class({"demo": {"url": server.url, "name": "Demo Tool"}})
        outcome = _run_install(worker_class("demo", tmp_path / "install"))

    assert len(outcome.finished) == 1
    success, message = outcome.finished[0]
    assert success is False
    assert message.startswith("Download failed: ")
    assert outcome.progress == [3, 5, 10]


@pytest.mark.usefixtures("direct_network")
def test_x64dbg_install_resolves_release_asset_and_extracts(tmp_path: Path) -> None:
    """x64dbg is resolved through the release API: the first ``.zip`` asset is downloaded and extracted.

    Args:
        tmp_path: Per-test temporary directory.
    """
    archive = _zip_bytes({"release/x64/x64dbg.exe": b"MZ"})
    install_path = tmp_path / "install"
    with RouteServer() as server:
        server.script(
            "GET",
            "/api/snapshot",
            json_response(
                200,
                {
                    "assets": [
                        {"name": "notes.txt", "browser_download_url": f"{server.origin}/files/notes.txt"},
                        {"name": "snapshot_2026-10-01.zip", "browser_download_url": f"{server.origin}/files/snapshot.zip"},
                    ],
                },
            ),
        )
        server.script("GET", "/files/snapshot.zip", ScriptedResponse(headers=(("content-type", "application/zip"),), chunks=(archive,)))
        worker_class = _worker_class({"x64dbg": {"api_url": f"{server.origin}/api/snapshot", "name": "x64dbg Snapshot"}})
        outcome = _run_install(worker_class("x64dbg", install_path))
        notes_requests = server.requests("/files/notes.txt")
        snapshot_requests = server.requests("/files/snapshot.zip")

    assert outcome.finished == [(True, "x64dbg Snapshot installed successfully")]
    assert outcome.progress == [3, 5, 10, 85, 95, 100]
    assert (install_path / "release" / "x64" / "x64dbg.exe").read_bytes() == b"MZ"
    assert notes_requests == []
    assert len(snapshot_requests) == 1


@pytest.mark.usefixtures("direct_network")
def test_cutter_install_selects_asset_sends_api_headers_and_extracts(tmp_path: Path) -> None:
    """Cutter is resolved through the release API with the documented GitHub headers and its executable is found after extraction.

    Args:
        tmp_path: Per-test temporary directory.
    """
    archive = _zip_bytes({"Cutter-v2.4-Windows-x86_64/cutter.exe": b"MZ"})
    install_path = tmp_path / "install"
    with RouteServer() as server:
        server.script(
            "GET",
            _API_PATH,
            json_response(
                200,
                {
                    "assets": [
                        {"name": "Cutter-v2.4-src.tar.gz", "browser_download_url": f"{server.origin}/files/src.tar.gz"},
                        {"name": "Cutter-v2.4-Windows-x86_64.zip", "browser_download_url": f"{server.origin}/files/cutter.zip"},
                    ],
                },
            ),
        )
        server.script("GET", "/files/cutter.zip", ScriptedResponse(headers=(("content-type", "application/zip"),), chunks=(archive,)))
        urls = {
            "cutter": {
                "api_url": f"{server.origin}{_API_PATH}",
                "fallback_html": f"{server.origin}/releases",
                "name": "Cutter",
            },
        }
        outcome = _run_install(_worker_class(urls)("cutter", install_path))
        api_requests = server.requests(_API_PATH)
        archive_requests = server.requests("/files/cutter.zip")

    assert outcome.finished == [(True, "Cutter installed successfully")]
    assert outcome.progress == [3, 5, 10, 85, 95, 100]
    assert (install_path / "Cutter-v2.4-Windows-x86_64" / "cutter.exe").read_bytes() == b"MZ"
    assert len(api_requests) == 1
    assert api_requests[0].headers["accept"] == "application/vnd.github+json"
    assert api_requests[0].headers["user-agent"] == "Intellicrack-ToolInstaller"
    assert api_requests[0].headers["x-github-api-version"] == "2022-11-28"
    assert len(archive_requests) == 1


@pytest.mark.usefixtures("direct_network")
def test_ghidra_install_without_ghidra_directory_fails_in_post_install(tmp_path: Path) -> None:
    """An archive with no Ghidra tree extracts, then the run reports the missing installation as a failure.

    Args:
        tmp_path: Per-test temporary directory.
    """
    body = _zip_bytes({"docs/readme.txt": b"no ghidra here"})
    install_path = tmp_path / "install"
    with RouteServer() as server:
        server.script("GET", "/ghidra.zip", ScriptedResponse(headers=(("content-type", "application/zip"),), chunks=(body,)))
        worker_class = _worker_class({"ghidra": {"url": f"{server.origin}/ghidra.zip", "name": "Ghidra Test"}})
        outcome = _run_install(worker_class("ghidra", install_path))

    assert outcome.finished == [(False, "Installation failed: Ghidra installation not found after extraction")]
    assert outcome.progress == [3, 5, 10, 85, 95]
    assert (install_path / "docs" / "readme.txt").read_bytes() == b"no ghidra here"


def test_resolve_returns_direct_url_unchanged(tmp_path: Path) -> None:
    """An entry with a direct URL is used as given, with no error text.

    Args:
        tmp_path: Per-test temporary directory.
    """
    worker = ToolInstallWorker("demo", tmp_path)

    result = _call(worker, "_resolve_download_url", {"url": "http://host.invalid/tool.zip", "name": "Demo"})

    assert result == ("http://host.invalid/tool.zip", "")


def test_resolve_without_any_url_reports_missing_configuration(tmp_path: Path) -> None:
    """An entry with neither a direct URL nor an API URL is reported as unconfigured.

    Args:
        tmp_path: Per-test temporary directory.
    """
    worker = ToolInstallWorker("demo", tmp_path)

    result = _call(worker, "_resolve_download_url", {"name": "Demo"})

    assert result == (None, "No download URL configured for demo")


@pytest.mark.usefixtures("direct_network")
def test_resolve_appends_manual_download_hint_only_when_fallback_is_configured(tmp_path: Path) -> None:
    """A release lookup failure names the manual-download page only for tools that have one.

    Args:
        tmp_path: Per-test temporary directory.
    """
    worker = ToolInstallWorker("demo", tmp_path)
    with RouteServer() as server:
        server.script("GET", _API_PATH, json_response(404, {}), json_response(404, {}))
        api_url = f"{server.origin}{_API_PATH}"
        with_hint = _call(worker, "_resolve_download_url", {"api_url": api_url, "fallback_html": "http://host.invalid/releases"})
        without_hint = _call(worker, "_resolve_download_url", {"api_url": api_url})

    assert with_hint == (None, "GitHub release not found (HTTP 404). Download manually from: http://host.invalid/releases")
    assert without_hint == (None, "GitHub release not found (HTTP 404)")


@pytest.mark.usefixtures("direct_network")
def test_resolve_reports_release_without_assets(tmp_path: Path) -> None:
    """A release that lists no assets is reported with the tool name and the manual-download hint.

    Args:
        tmp_path: Per-test temporary directory.
    """
    worker = ToolInstallWorker("x64dbg", tmp_path)
    with RouteServer() as server:
        server.script("GET", _API_PATH, json_response(200, {"assets": []}))
        result = _call(
            worker,
            "_resolve_download_url",
            {"api_url": f"{server.origin}{_API_PATH}", "fallback_html": "http://host.invalid/releases"},
        )

    assert result == (None, "No release assets found for x64dbg. Download manually from: http://host.invalid/releases")


@pytest.mark.usefixtures("direct_network")
def test_resolve_reports_release_without_compatible_asset(tmp_path: Path) -> None:
    """Assets that do not match the tool's patterns are reported as no compatible asset.

    Args:
        tmp_path: Per-test temporary directory.
    """
    worker = ToolInstallWorker("x64dbg", tmp_path)
    assets = [{"name": "notes.txt", "browser_download_url": "http://host.invalid/notes.txt"}]
    with RouteServer() as server:
        server.script("GET", _API_PATH, json_response(200, {"assets": assets}))
        result = _call(worker, "_resolve_download_url", {"api_url": f"{server.origin}{_API_PATH}"})

    assert result == (None, "No compatible asset found for x64dbg on this platform")


@pytest.mark.usefixtures("direct_network")
def test_resolve_for_tool_without_asset_patterns_finds_no_asset(tmp_path: Path) -> None:
    """A tool that has no asset naming rules never matches a release asset.

    Args:
        tmp_path: Per-test temporary directory.
    """
    worker = ToolInstallWorker("demo", tmp_path)
    assets = [{"name": "demo.zip", "browser_download_url": "http://host.invalid/demo.zip"}]
    with RouteServer() as server:
        server.script("GET", _API_PATH, json_response(200, {"assets": assets}))
        result = _call(worker, "_resolve_download_url", {"api_url": f"{server.origin}{_API_PATH}"})

    assert result == (None, "No compatible asset found for demo on this platform")


@pytest.mark.usefixtures("direct_network")
def test_resolve_skips_assets_without_a_usable_url(tmp_path: Path) -> None:
    """Assets with an empty or missing download URL, or a non-matching name, are skipped in favor of the first usable ``.zip``.

    Args:
        tmp_path: Per-test temporary directory.
    """
    worker = ToolInstallWorker("x64dbg", tmp_path)
    assets = [
        {"name": "empty.zip", "browser_download_url": ""},
        {"name": "nourl.zip"},
        {"name": "notes.txt", "browser_download_url": "http://host.invalid/notes.txt"},
        {"name": "snapshot.zip", "browser_download_url": "http://host.invalid/snapshot.zip"},
        {"name": "later.zip", "browser_download_url": "http://host.invalid/later.zip"},
    ]
    with RouteServer() as server:
        server.script("GET", _API_PATH, json_response(200, {"assets": assets}))
        result = _call(worker, "_resolve_download_url", {"api_url": f"{server.origin}{_API_PATH}"})

    assert result == ("http://host.invalid/snapshot.zip", "")


def test_cutter_asset_choice_follows_the_running_platform(tmp_path: Path) -> None:
    """The Cutter asset for the running operating system is preferred over the other platforms' builds.

    Args:
        tmp_path: Per-test temporary directory.
    """
    assets: list[dict[str, object]] = [
        {"name": "Cutter-v2-Linux-x86_64.AppImage", "browser_download_url": "http://host.invalid/linux"},
        {"name": "Cutter-v2-macOS-x86_64.dmg", "browser_download_url": "http://host.invalid/macos"},
        {"name": "Cutter-v2-Windows-x86_64.zip", "browser_download_url": "http://host.invalid/windows"},
    ]
    expected_by_system = {
        "Windows": "http://host.invalid/windows",
        "Linux": "http://host.invalid/linux",
        "Darwin": "http://host.invalid/macos",
    }

    chosen = _call(ToolInstallWorker("cutter", tmp_path), "_select_asset_url", assets)

    assert chosen == expected_by_system.get(platform.system(), "http://host.invalid/windows")


def test_with_fallback_adds_hint_only_for_non_empty_fallback() -> None:
    """The manual-download hint is appended exactly when a fallback page is given."""
    assert (
        _call(ToolInstallWorker, "_with_fallback", "Broken", "http://host.invalid/r")
        == "Broken. Download manually from: http://host.invalid/r"
    )
    assert _call(ToolInstallWorker, "_with_fallback", "Broken", "") == "Broken"


@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (403, (("x-ratelimit-remaining", "0"),), "GitHub API rate limit exceeded; try again later"),
        (403, (("x-ratelimit-remaining", "12"),), "GitHub API request forbidden (HTTP 403)"),
        (403, (), "GitHub API request forbidden (HTTP 403)"),
        (404, (), "GitHub release not found (HTTP 404)"),
        (500, (), "GitHub API returned HTTP 500"),
    ],
    ids=["rate-limited", "forbidden-with-quota", "forbidden-without-header", "not-found", "server-error"],
)
@pytest.mark.usefixtures("direct_network")
def test_fetch_release_maps_http_status_to_message(status: int, headers: tuple[tuple[str, str], ...], expected: str) -> None:
    """Each non-success GitHub API status is turned into its documented message and no data.

    Args:
        status: HTTP status the server answers with.
        headers: Extra response headers.
        expected: Message the fetch is expected to report.
    """
    with RouteServer() as server:
        server.script("GET", _API_PATH, json_response(status, {}, headers))
        result = _call(ToolInstallWorker, "_fetch_github_release", f"{server.origin}{_API_PATH}")

    assert result == (None, expected)


@pytest.mark.usefixtures("direct_network")
def test_fetch_release_returns_parsed_json_on_success() -> None:
    """A 200 response is parsed and returned with an empty error message."""
    payload = {"tag_name": "v1.2.3", "assets": [{"name": "tool.zip", "browser_download_url": "http://host.invalid/tool.zip"}]}
    with RouteServer() as server:
        server.script("GET", _API_PATH, json_response(200, payload))
        result = _call(ToolInstallWorker, "_fetch_github_release", f"{server.origin}{_API_PATH}")

    assert result == (payload, "")


@pytest.mark.usefixtures("direct_network")
def test_fetch_release_reports_unparseable_json() -> None:
    """A 200 response whose body is not JSON is reported as unparseable."""
    with RouteServer() as server:
        server.script("GET", _API_PATH, ScriptedResponse(status=200, chunks=(b"{not valid json",)))
        result = _call(ToolInstallWorker, "_fetch_github_release", f"{server.origin}{_API_PATH}")

    assert result == (None, "Failed to parse GitHub API response")


@pytest.mark.usefixtures("direct_network")
def test_fetch_release_reports_connection_refused() -> None:
    """An unreachable API host is reported as a connection failure."""
    result = _call(ToolInstallWorker, "_fetch_github_release", f"http://127.0.0.1:{_closed_port()}{_API_PATH}")

    assert result == (None, "Could not connect to GitHub API")


@pytest.mark.usefixtures("direct_network")
def test_fetch_release_reports_response_cut_short() -> None:
    """A response closed before its announced body arrives is reported as a failed API request."""
    with _TruncatingServer(status=200, body=b"x" * 6000) as server:
        result = cast("tuple[object, str]", _call(ToolInstallWorker, "_fetch_github_release", server.url))

    assert result[0] is None
    assert result[1].startswith("GitHub API request failed: ")


def test_find_cutter_executable_prefers_the_install_root(tmp_path: Path) -> None:
    """``cutter.exe`` directly in the install directory wins over one in a subdirectory.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "cutter"
    (install_path / "nested").mkdir(parents=True)
    (install_path / "nested" / "cutter.exe").write_bytes(b"MZ")
    (install_path / "cutter.exe").write_bytes(b"MZ")

    found = cast("Path | None", _call(ToolInstallWorker("cutter", install_path), "_find_cutter_executable"))

    assert found == install_path / "cutter.exe"


def test_find_cutter_executable_searches_subdirectories(tmp_path: Path) -> None:
    """``cutter.exe`` is found inside an extracted subdirectory, skipping directories that lack it.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "cutter"
    (install_path / "alpha").mkdir(parents=True)
    (install_path / "nested").mkdir()
    (install_path / "nested" / "cutter.exe").write_bytes(b"MZ")

    found = cast("Path | None", _call(ToolInstallWorker("cutter", install_path), "_find_cutter_executable"))

    assert found == install_path / "nested" / "cutter.exe"


def test_find_cutter_executable_returns_none_when_absent(tmp_path: Path) -> None:
    """An install directory with no ``cutter.exe`` anywhere yields nothing.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "cutter"
    (install_path / "alpha").mkdir(parents=True)

    found = _call(ToolInstallWorker("cutter", install_path), "_find_cutter_executable")

    assert found is None


def test_post_install_cutter_tolerates_missing_executable(tmp_path: Path) -> None:
    """The Cutter post-install step does not fail, or create anything, when the executable cannot be found.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "cutter"
    install_path.mkdir()

    result = _call(ToolInstallWorker("cutter", install_path), "_post_install_cutter")

    assert result is None
    assert list(install_path.iterdir()) == []


def test_post_install_ghidra_requires_an_extracted_installation(tmp_path: Path) -> None:
    """The Ghidra post-install step raises when the install directory holds no Ghidra tree.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "ghidra"
    (install_path / "docs").mkdir(parents=True)
    worker = ToolInstallWorker("ghidra", install_path)

    with pytest.raises(RuntimeError, match=r"^Ghidra installation not found after extraction$"):
        _ = _call(worker, "_post_install_ghidra")


@pytest.mark.spawns_process
@pytest.mark.usefixtures("offline_pip")
def test_post_install_ghidra_reports_failed_bridge_package_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing ``pip install ghidra_bridge`` aborts the post-install step with pip's own error text.

    A Ghidra tree laid out at the install root is accepted, so the step reaches pip. Requiring a virtual environment makes pip refuse to
    run in the conda-style test environment, without touching any index.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the environment.
    """
    monkeypatch.setenv("PIP_REQUIRE_VIRTUALENV", "1")
    install_path = tmp_path / "ghidra"
    (install_path / "support").mkdir(parents=True)
    (install_path / "support" / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    worker = ToolInstallWorker("ghidra", install_path)

    with pytest.raises(RuntimeError, match=r"(?s)^Failed to install ghidra_bridge:.*virtualenv"):
        _ = _call(worker, "_post_install_ghidra")

    assert not (install_path / "ghidra_scripts").exists()


@pytest.mark.spawns_process
@pytest.mark.usefixtures("offline_pip")
def test_post_install_ghidra_writes_bridge_scripts(tmp_path: Path) -> None:
    """The Ghidra post-install step writes the bridge script, extension files, headless wrapper and verify script.

    Args:
        tmp_path: Per-test temporary directory.
    """
    root = _install_ghidra_bridge_files(tmp_path)

    scripts_copy = (root / "ghidra_scripts" / "intellicrack_bridge.py").read_text(encoding="utf-8")
    extension_dir = root / "Extensions" / "intellicrack_bridge"
    extension_copy = (extension_dir / "intellicrack_bridge.py").read_text(encoding="utf-8")
    assert scripts_copy.startswith("import ghidra_bridge_server\n")
    assert 'server_host="127.0.0.1"' in scripts_copy
    assert "server_port=4768" in scripts_copy
    assert extension_copy == scripts_copy

    headless = (root / "support" / "intellicrack_headless_bridge.bat").read_text(encoding="utf-8")
    assert headless.startswith("@echo off\n")
    assert "analyzeHeadless.bat" in headless
    assert "-scriptPath" in headless
    assert "-postScript intellicrack_bridge.py" in headless

    install_script = ast.parse((extension_dir / "install_bridge.py").read_text(encoding="utf-8"))
    assert any(isinstance(node, ast.FunctionDef) and node.name == "main" for node in install_script.body)
    verify_text = (root / "verify_intellicrack_bridge.py").read_text(encoding="utf-8")
    _ = ast.parse(verify_text)
    assert "4768" in verify_text


@pytest.mark.spawns_process
@pytest.mark.usefixtures("offline_pip")
def test_generated_install_script_restores_bridge_script_into_ghidra_scripts(tmp_path: Path) -> None:
    """Running the generated ``install_bridge.py`` copies the bridge script into the Ghidra root's ``ghidra_scripts`` directory.

    The script is written to ``<root>/Extensions/intellicrack_bridge`` and derives the Ghidra root from its own location, so the copy is
    expected to land in ``<root>/ghidra_scripts``.

    Args:
        tmp_path: Per-test temporary directory.
    """
    root = _install_ghidra_bridge_files(tmp_path)
    scripts_copy = root / "ghidra_scripts" / "intellicrack_bridge.py"
    expected = scripts_copy.read_text(encoding="utf-8")
    scripts_copy.unlink()

    _ = runpy.run_path(str(root / "Extensions" / "intellicrack_bridge" / "install_bridge.py"), run_name="__main__")

    assert scripts_copy.is_file()
    assert scripts_copy.read_text(encoding="utf-8") == expected


@pytest.mark.parametrize("tool_id", ["process", "binary"])
def test_in_process_tools_report_built_in(tool_id: str) -> None:
    """Tools implemented inside Intellicrack are always reported available, whatever path is configured.

    Args:
        tool_id: The built-in tool identifier.
    """
    assert _run_status(tool_id, "") == (tool_id, True, _BUILTIN_STATUS)


def test_frida_status_reports_installed_version() -> None:
    """The Frida check reports availability with a real version number taken from the installed module."""
    tool_id, available, message = _run_status("frida", "")

    assert tool_id == "frida"
    assert available is True
    assert message.startswith("Frida ")
    assert message.endswith(" available")
    version = message.removeprefix("Frida ").removesuffix(" available")
    assert version != "unknown"
    assert version[:1].isdigit()


def test_status_without_configured_path_is_unavailable() -> None:
    """An external tool with no configured path is reported as not configured."""
    assert _run_status("ghidra", "") == ("ghidra", False, "Path not configured")


def test_status_with_missing_path_is_unavailable(tmp_path: Path) -> None:
    """A configured path that does not exist is reported as such.

    Args:
        tmp_path: Per-test temporary directory.
    """
    assert _run_status("x64dbg", str(tmp_path / "absent")) == ("x64dbg", False, "Path does not exist")


def test_status_of_unrecognized_tool_with_existing_path_is_installed(tmp_path: Path) -> None:
    """A tool the checker has no special rule for is installed when its path exists.

    Args:
        tmp_path: Per-test temporary directory.
    """
    assert _run_status("radare2", str(tmp_path)) == ("radare2", True, "Installed")


@pytest.mark.parametrize("layout", _GHIDRA_FOUND_LAYOUTS, ids=_GHIDRA_FOUND_IDS)
def test_ghidra_status_finds_headless_launcher(layout: tuple[str, ...], tmp_path: Path) -> None:
    """A Ghidra directory holding the headless launcher in any supported layout is reported installed.

    Args:
        layout: Relative files to create below the configured path.
        tmp_path: Per-test temporary directory.
    """
    _make_layout(tmp_path / "ghidra", layout)

    assert _run_status("ghidra", str(tmp_path / "ghidra")) == ("ghidra", True, "Ghidra installed")


@pytest.mark.parametrize("layout", _GHIDRA_MISSING_LAYOUTS, ids=_GHIDRA_MISSING_IDS)
def test_ghidra_status_without_headless_launcher_is_unavailable(layout: tuple[str, ...], tmp_path: Path) -> None:
    """A Ghidra directory without the headless launcher is reported as missing it.

    Args:
        layout: Relative files to create below the configured path.
        tmp_path: Per-test temporary directory.
    """
    _make_layout(tmp_path / "ghidra", layout)

    assert _run_status("ghidra", str(tmp_path / "ghidra")) == ("ghidra", False, "analyzeHeadless not found in installation")


@pytest.mark.parametrize("relative", _X64DBG_LAYOUTS)
def test_x64dbg_status_finds_each_supported_executable_location(relative: str, tmp_path: Path) -> None:
    """Each supported location of the x64dbg executable makes the tool installed.

    Args:
        relative: Executable location relative to the configured path.
        tmp_path: Per-test temporary directory.
    """
    _make_layout(tmp_path / "x64dbg", (relative,))

    assert _run_status("x64dbg", str(tmp_path / "x64dbg")) == ("x64dbg", True, "x64dbg installed")


def test_x64dbg_status_without_executable_is_unavailable(tmp_path: Path) -> None:
    """An x64dbg directory with no debugger executable is reported as lacking it.

    Args:
        tmp_path: Per-test temporary directory.
    """
    _make_layout(tmp_path / "x64dbg", ("readme.txt",))

    assert _run_status("x64dbg", str(tmp_path / "x64dbg")) == ("x64dbg", False, "x64dbg.exe not found")


def test_cutter_status_finds_executable_in_install_root(tmp_path: Path) -> None:
    """``cutter.exe`` directly in the configured directory makes Cutter installed.

    Args:
        tmp_path: Per-test temporary directory.
    """
    _make_layout(tmp_path / "cutter", ("cutter.exe",))

    assert _run_status("cutter", str(tmp_path / "cutter")) == ("cutter", True, "Cutter installed")


def test_cutter_status_finds_executable_in_subdirectory(tmp_path: Path) -> None:
    """``cutter.exe`` inside an extracted subdirectory makes Cutter installed, past files and directories that lack it.

    Args:
        tmp_path: Per-test temporary directory.
    """
    _make_layout(tmp_path / "cutter", ("alpha.txt", "beta/readme.txt", "gamma/cutter.exe"))

    assert _run_status("cutter", str(tmp_path / "cutter")) == ("cutter", True, "Cutter installed")


@pytest.mark.spawns_process
@pytest.mark.usefixtures("empty_path")
def test_cutter_status_without_executable_or_path_entry_is_unavailable(tmp_path: Path) -> None:
    """With no ``cutter.exe`` on disk and none on ``PATH``, Cutter is reported as not found.

    Args:
        tmp_path: Per-test temporary directory.
    """
    _make_layout(tmp_path / "cutter", ("readme.txt",))

    assert _run_status("cutter", str(tmp_path / "cutter")) == ("cutter", False, "Cutter executable not found")


@pytest.mark.spawns_process
@pytest.mark.usefixtures("empty_path")
def test_cutter_check_of_missing_directory_falls_through_to_path_probe(tmp_path: Path) -> None:
    """The Cutter check on a directory that does not exist still probes ``PATH`` and reports not found.

    Args:
        tmp_path: Per-test temporary directory.
    """
    result = _call(ToolStatusCheckWorker, "_check_cutter", tmp_path / "absent")

    assert result == (False, "Cutter executable not found")


@pytest.mark.spawns_process
def test_cutter_check_survives_unlaunchable_path_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``cutter.exe`` on ``PATH`` that the operating system cannot launch is reported as not found, not as an error.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the environment.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "cutter.exe").write_bytes(b"this is not an executable image")
    monkeypatch.setenv("PATH", str(bin_dir))
    install_path = tmp_path / "cutter"
    install_path.mkdir()

    assert _run_status("cutter", str(install_path)) == ("cutter", False, "Cutter executable not found")


def test_status_check_failure_is_reported_as_unavailable(tmp_path: Path) -> None:
    """An operating-system error while checking becomes an unavailable result carrying the error text.

    Args:
        tmp_path: Per-test temporary directory.
    """
    not_a_directory = tmp_path / "ghidra.txt"
    not_a_directory.write_text("plain file", encoding="utf-8")

    tool_id, available, message = _run_status("ghidra", str(not_a_directory))

    assert tool_id == "ghidra"
    assert available is False
    assert message.startswith("Check failed: ")


@pytest.mark.usefixtures("state_dir")
def test_tool_config_dialog_lists_every_tool_with_defaults(qtbot: QtBot, tmp_path: Path) -> None:
    """The dialog lists the six tools in order, selects the first and shows each tool's default path.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        tmp_path: Per-test temporary directory.
    """
    tools_directory = tmp_path / "tools"
    dialog = ToolConfigDialog(tools_directory=tools_directory)
    qtbot.addWidget(dialog)

    tool_list = _attr(dialog, "_tool_list", QListWidget)
    stack = _attr(dialog, "_settings_stack", QStackedWidget)
    widgets = cast("dict[str, ToolSettingsWidget]", getattr(dialog, "_tool_widgets"))
    assert _row_texts(tool_list) == list(_DISPLAY_NAMES)
    roles: list[object] = []
    for row in range(tool_list.count()):
        item = tool_list.item(row)
        assert item is not None
        roles.append(item.data(Qt.ItemDataRole.UserRole))
    assert roles == list(_TOOL_IDS)
    assert stack.count() == 6
    assert tool_list.currentRow() == 0
    assert stack.currentIndex() == 0
    assert list(widgets) == list(_TOOL_IDS)
    defaults = {tool_id: widgets[tool_id].get_settings()["path"] for tool_id in _TOOL_IDS}
    assert defaults == {
        "ghidra": str(tools_directory / "ghidra"),
        "x64dbg": str(tools_directory / "x64dbg"),
        "frida": "",
        "cutter": str(tools_directory / "cutter"),
        "process": "",
        "binary": "",
    }


@pytest.mark.usefixtures("state_dir")
def test_tool_config_dialog_row_selection_switches_page(qtbot: QtBot, tmp_path: Path) -> None:
    """Selecting a row shows that tool's page, and out-of-range selections leave the page alone.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        tmp_path: Per-test temporary directory.
    """
    dialog = ToolConfigDialog(tools_directory=tmp_path / "tools")
    qtbot.addWidget(dialog)
    tool_list = _attr(dialog, "_tool_list", QListWidget)
    stack = _attr(dialog, "_settings_stack", QStackedWidget)
    widgets = cast("dict[str, ToolSettingsWidget]", getattr(dialog, "_tool_widgets"))

    tool_list.setCurrentRow(3)
    assert stack.currentIndex() == 3
    assert stack.currentWidget() is widgets["cutter"]

    _ = _call(dialog, "_on_tool_selected", -1)
    _ = _call(dialog, "_on_tool_selected", 99)
    assert stack.currentIndex() == 3


def test_tool_config_dialog_apply_saves_every_tool_and_announces_updates(qtbot: QtBot, tmp_path: Path, state_dir: Path) -> None:
    """Apply writes all six tools to ``tools.json`` and emits ``tool_updated`` for each, in list order.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        tmp_path: Per-test temporary directory.
        state_dir: Configuration directory the dialog is redirected to.
    """
    dialog = ToolConfigDialog(tools_directory=tmp_path / "tools")
    qtbot.addWidget(dialog)
    updates = _record(dialog.tool_updated)
    widgets = cast("dict[str, ToolSettingsWidget]", getattr(dialog, "_tool_widgets"))
    custom = tmp_path / "custom-ghidra"
    _attr(widgets["ghidra"], "_path_input", QLineEdit).setText(str(custom))
    _attr(widgets["ghidra"], "_enabled_checkbox", QCheckBox).setChecked(False)
    _attr(widgets["ghidra"], "_timeout_spin", QSpinBox).setValue(120)

    _ = _call(dialog, "_on_apply")

    assert updates.calls == [(tool_id,) for tool_id in _TOOL_IDS]
    saved = cast("dict[str, dict[str, object]]", json.loads((state_dir / "tools.json").read_text(encoding="utf-8")))
    assert list(saved) == list(_TOOL_IDS)
    assert saved["ghidra"] == {"enabled": False, "path": str(custom), "auto_install": True, "startup_timeout_seconds": 120}
    assert saved["frida"] == {"enabled": True, "path": "", "auto_install": True, "startup_timeout_seconds": 60}


def test_tool_config_dialog_accept_saves_and_closes(qtbot: QtBot, tmp_path: Path, state_dir: Path) -> None:
    """OK saves the settings and accepts the dialog.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        tmp_path: Per-test temporary directory.
        state_dir: Configuration directory the dialog is redirected to.
    """
    dialog = ToolConfigDialog(tools_directory=tmp_path / "tools")
    qtbot.addWidget(dialog)
    widgets = cast("dict[str, ToolSettingsWidget]", getattr(dialog, "_tool_widgets"))
    _attr(widgets["x64dbg"], "_path_input", QLineEdit).setText(str(tmp_path / "dbg"))
    assert dialog.result() == QDialog.DialogCode.Rejected.value

    _ = _call(dialog, "_on_accept")

    assert dialog.result() == QDialog.DialogCode.Accepted.value
    saved = cast("dict[str, dict[str, object]]", json.loads((state_dir / "tools.json").read_text(encoding="utf-8")))
    assert saved["x64dbg"]["path"] == str(tmp_path / "dbg")


@pytest.mark.usefixtures("state_dir")
def test_tool_config_dialog_get_settings_collects_each_tool(qtbot: QtBot, tmp_path: Path) -> None:
    """``get_settings`` returns one settings dictionary per tool reflecting the current form values.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        tmp_path: Per-test temporary directory.
    """
    dialog = ToolConfigDialog(tools_directory=tmp_path / "tools")
    qtbot.addWidget(dialog)
    widgets = cast("dict[str, ToolSettingsWidget]", getattr(dialog, "_tool_widgets"))
    _attr(widgets["ghidra"], "_auto_install_checkbox", QCheckBox).setChecked(False)
    _attr(widgets["ghidra"], "_timeout_spin", QSpinBox).setValue(45)

    settings = dialog.get_settings()

    assert list(settings) == list(_TOOL_IDS)
    assert settings["ghidra"] == {
        "enabled": True,
        "path": str(tmp_path / "tools" / "ghidra"),
        "auto_install": False,
        "startup_timeout_seconds": 45,
    }
    assert settings["frida"] == {"enabled": True, "path": "", "auto_install": True, "startup_timeout_seconds": 60}


@pytest.mark.parametrize("tool_id", ["x64dbg", "cutter"])
def test_missing_pefile_disables_pe_tool_installer_controls(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_id: str,
) -> None:
    """Without the optional ``pefile`` dependency the PE tools cannot be installed, and the form says so.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the availability flag.
        tool_id: The PE-dependent tool identifier.
    """
    monkeypatch.setattr(installer_module, "_pefile_available", False)

    widget = _make_widget(qtbot, tmp_path, tool_id, tool_id)

    install_button = _attr(widget, "_install_btn", QPushButton)
    auto_install = _attr(widget, "_auto_install_checkbox", QCheckBox)
    assert not install_button.isEnabled()
    assert install_button.toolTip() == "Installation disabled: 'pefile' dependency is missing."
    assert not auto_install.isEnabled()
    assert not auto_install.isChecked()


def test_missing_pefile_leaves_ghidra_installer_controls_enabled(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ghidra does not need ``pefile``, so its installer controls stay usable without it.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the availability flag.
    """
    monkeypatch.setattr(installer_module, "_pefile_available", False)

    widget = _make_widget(qtbot, tmp_path)

    assert _attr(widget, "_install_btn", QPushButton).isEnabled()
    assert _attr(widget, "_auto_install_checkbox", QCheckBox).isEnabled()
    assert _attr(widget, "_auto_install_checkbox", QCheckBox).isChecked()


def test_saved_settings_populate_the_form(qtbot: QtBot, tmp_path: Path) -> None:
    """Values stored for the tool in ``tools.json`` fill the form, and other tools' entries are ignored.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    config_path = _write_tool_settings(
        tmp_path,
        {
            "ghidra": {"path": str(tmp_path / "elsewhere"), "enabled": False, "auto_install": False, "startup_timeout_seconds": 90},
            "x64dbg": {"path": "ignored"},
        },
    )

    widget = _make_widget(qtbot, tmp_path, config_path=config_path)

    assert widget.get_settings() == {
        "enabled": False,
        "path": str(tmp_path / "elsewhere"),
        "auto_install": False,
        "startup_timeout_seconds": 90,
    }


def test_settings_file_without_entry_for_tool_uses_defaults(qtbot: QtBot, tmp_path: Path) -> None:
    """A ``tools.json`` that has no entry for the tool leaves the form at its defaults.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    config_path = _write_tool_settings(tmp_path, {"x64dbg": {"path": "other"}})

    widget = _make_widget(qtbot, tmp_path, config_path=config_path)

    assert widget.get_settings() == {
        "enabled": True,
        "path": str(tmp_path / "tools" / "ghidra"),
        "auto_install": True,
        "startup_timeout_seconds": 60,
    }


def test_corrupt_settings_file_falls_back_to_defaults(qtbot: QtBot, tmp_path: Path) -> None:
    """A ``tools.json`` that is not valid JSON is ignored and the form shows its defaults.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    config_path = tmp_path / "tools.json"
    config_path.write_text("{this is not json", encoding="utf-8")

    widget = _make_widget(qtbot, tmp_path, config_path=config_path)

    assert widget.get_settings()["path"] == str(tmp_path / "tools" / "ghidra")
    assert widget.get_settings()["startup_timeout_seconds"] == 60


def test_unreadable_settings_file_falls_back_to_defaults(qtbot: QtBot, tmp_path: Path) -> None:
    """A settings path the operating system cannot read as a file is ignored and the form shows its defaults.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    config_path = tmp_path / "tools.json"
    config_path.mkdir()

    widget = _make_widget(qtbot, tmp_path, config_path=config_path)

    assert widget.get_settings()["path"] == str(tmp_path / "tools" / "ghidra")
    assert widget.get_settings()["enabled"] is True


def test_browse_places_selected_directory_in_path_field(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing a directory in the Browse dialog fills the path field and the dialog opens at the tools directory.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the file dialog.
    """
    chosen = tmp_path / "picked"
    requests: list[tuple[str, str]] = []

    def _pick(_parent: object, caption: str, directory: str) -> str:
        """Report a fixed directory as the user's choice.

        Args:
            _parent: Parent widget passed by the caller.
            caption: Dialog caption.
            directory: Directory the dialog opens at.

        Returns:
            str: The chosen directory.
        """
        requests.append((caption, directory))
        return str(chosen)

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", _pick)
    widget = _make_widget(qtbot, tmp_path)

    _attr(widget, "_browse_btn", QPushButton).click()

    assert _attr(widget, "_path_input", QLineEdit).text() == str(chosen)
    assert requests == [("Select Ghidra Installation", str(tmp_path / "tools"))]


def test_cancelled_browse_keeps_existing_path(qtbot: QtBot, tmp_path: Path) -> None:
    """Cancelling the Browse dialog leaves the path field as it was.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    widget = _make_widget(qtbot, tmp_path)
    path_input = _attr(widget, "_path_input", QLineEdit)
    path_input.setText("keep-me")

    _attr(widget, "_browse_btn", QPushButton).click()

    assert path_input.text() == "keep-me"


def test_available_status_shows_success_icon_and_message(qtbot: QtBot, tmp_path: Path) -> None:
    """An available result shows the success icon and the message, re-enables Check Status and announces the change.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    widget = _make_widget(qtbot, tmp_path)
    changes = _record(widget.status_changed)
    check_button = _attr(widget, "_check_status_btn", QPushButton)
    check_button.setEnabled(False)

    _ = _call(widget, "_on_status_checked", "ghidra", is_available=True, message="Ghidra installed")

    icons = IconManager.get_instance()
    success_image = icons.get_pixmap("status_success", 16).toImage()
    assert success_image != icons.get_pixmap("status_error", 16).toImage()
    assert _attr(widget, "_status_icon", QLabel).pixmap().toImage() == success_image
    assert widget.status_label.text() == "Ghidra installed"
    assert check_button.isEnabled()
    assert changes.calls == [("ghidra", True)]


def test_unavailable_status_shows_error_icon_and_message(qtbot: QtBot, tmp_path: Path) -> None:
    """An unavailable result shows the error icon and the message and announces the change.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    widget = _make_widget(qtbot, tmp_path)
    changes = _record(widget.status_changed)

    _ = _call(widget, "_on_status_checked", "ghidra", is_available=False, message="Path does not exist")

    error_image = IconManager.get_instance().get_pixmap("status_error", 16).toImage()
    assert _attr(widget, "_status_icon", QLabel).pixmap().toImage() == error_image
    assert widget.status_label.text() == "Path does not exist"
    assert changes.calls == [("ghidra", False)]


@pytest.mark.parametrize(("tool_id", "display_name"), [("frida", "Frida"), ("process", "Process Control"), ("binary", "Binary Operations")])
def test_installing_built_in_tool_explains_nothing_to_install(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_id: str,
    display_name: str,
) -> None:
    """Install on a built-in tool tells the user nothing needs installing and starts no worker.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the message box.
        tool_id: The built-in tool identifier.
        display_name: The tool's display name.
    """
    information = _capture_dialog(monkeypatch, "information")
    widget = _make_widget(qtbot, tmp_path, tool_id, display_name)

    _ = _call(widget, "_install_tool")

    assert information == [("Installation", f"{display_name} is built-in and does not require installation.")]
    assert getattr(widget, "_install_worker") is None


def test_installing_tool_without_download_entry_warns(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Install on a tool with no download entry asks the user to install it manually.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the message box.
    """
    warnings = _capture_dialog(monkeypatch, "warning")
    widget = _make_widget(qtbot, tmp_path, "radare2", "Radare2")

    _ = _call(widget, "_install_tool")

    assert warnings == [("Installation", "Automatic installation not available for Radare2.\n\nPlease download and install manually.")]
    assert getattr(widget, "_install_worker") is None


@pytest.mark.parametrize("tool_id", ["x64dbg", "cutter"])
def test_installing_pe_tool_without_pefile_warns(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool_id: str) -> None:
    """Install on a PE tool without ``pefile`` explains the missing dependency and starts no worker.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the message box and the availability flag.
        tool_id: The PE-dependent tool identifier.
    """
    monkeypatch.setattr(installer_module, "_pefile_available", False)
    warnings = _capture_dialog(monkeypatch, "warning")
    widget = _make_widget(qtbot, tmp_path, tool_id, "Tool Name")

    _ = _call(widget, "_install_tool")

    assert warnings == [("Installation", "Cannot install Tool Name because optional dependency 'pefile' is missing.")]
    assert getattr(widget, "_install_worker") is None


def test_declined_install_prompt_starts_nothing(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Answering No to the install prompt leaves the controls untouched and starts no worker.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the message box.
    """
    questions = _capture_dialog(monkeypatch, "question", QMessageBox.StandardButton.No)
    widget = _make_widget(qtbot, tmp_path)
    target = tmp_path / "chosen-install"
    _attr(widget, "_path_input", QLineEdit).setText(str(target))

    _ = _call(widget, "_install_tool")

    assert questions == [("Install Tool", f"Download and install Ghidra?\n\nInstallation path:\n{target}")]
    assert getattr(widget, "_install_worker") is None
    assert _attr(widget, "_install_btn", QPushButton).isEnabled()
    assert _attr(widget, "_install_progress", QProgressBar).isHidden()
    assert not target.exists()


@pytest.mark.usefixtures("dead_proxy")
def test_accepted_install_runs_worker_and_reports_failure(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepting the install prompt starts a real worker whose result restores the controls and warns the user.

    Every request is routed to an unreachable loopback proxy, so the download fails at the first hop without leaving the machine.

    Args:
        qtbot: pytest-qt bot used to close the widget and wait for the worker's result.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the message boxes.
    """
    _ = _capture_dialog(monkeypatch, "question", QMessageBox.StandardButton.Yes)
    warnings = _capture_dialog(monkeypatch, "warning")
    widget = _make_widget(qtbot, tmp_path)
    install_button = _attr(widget, "_install_btn", QPushButton)
    progress_bar = _attr(widget, "_install_progress", QProgressBar)
    _attr(widget, "_path_input", QLineEdit).setText(str(tmp_path / "ghidra-install"))

    _ = _call(widget, "_install_tool")

    worker = _attr(widget, "_install_worker", ToolInstallWorker)
    try:
        assert worker.owner() is widget
        assert not progress_bar.isHidden()
        assert progress_bar.value() == 0
        assert not install_button.isEnabled()
        qtbot.waitUntil(install_button.isEnabled, timeout=_WAIT_MS)
    finally:
        assert worker.wait(_JOIN_MS)

    assert warnings == [("Installation Failed", "Could not connect to download server")]
    assert progress_bar.isHidden()
    assert (tmp_path / "ghidra-install").is_dir()


def test_install_success_notifies_and_rechecks_status(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful install tells the user, restores the controls and re-checks the tool's status.

    Args:
        qtbot: pytest-qt bot used to close the widget and wait for the re-check.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the message box.
    """
    information = _capture_dialog(monkeypatch, "information")
    install_path = tmp_path / "ghidra-install"
    _make_layout(install_path, ("ghidra_11.2/support/analyzeHeadless.bat",))
    widget = _make_widget(qtbot, tmp_path)
    _attr(widget, "_path_input", QLineEdit).setText(str(install_path))
    install_button = _attr(widget, "_install_btn", QPushButton)
    install_button.setEnabled(False)
    _attr(widget, "_install_progress", QProgressBar).setVisible(True)

    with qtbot.waitSignal(widget.status_changed, timeout=_WAIT_MS) as blocker:
        _ = _call(widget, "_on_install_finished", success=True, message="Ghidra 11.2.1 installed successfully")
    status_worker = _attr(widget, "_status_worker", ToolStatusCheckWorker)
    assert status_worker.wait(_JOIN_MS)

    assert information == [("Installation Complete", "Ghidra 11.2.1 installed successfully")]
    assert install_button.isEnabled()
    assert _attr(widget, "_install_progress", QProgressBar).isHidden()
    assert cast("list[object]", blocker.args) == ["ghidra", True]
    assert widget.status_label.text() == "Ghidra installed"


def test_install_failure_warns_and_restores_controls(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed install shows the failure text, restores the controls and does not re-check status.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the message box.
    """
    warnings = _capture_dialog(monkeypatch, "warning")
    widget = _make_widget(qtbot, tmp_path)
    install_button = _attr(widget, "_install_btn", QPushButton)
    install_button.setEnabled(False)
    _attr(widget, "_install_progress", QProgressBar).setVisible(True)

    _ = _call(widget, "_on_install_finished", success=False, message="boom")

    assert warnings == [("Installation Failed", "boom")]
    assert install_button.isEnabled()
    assert _attr(widget, "_install_progress", QProgressBar).isHidden()
    assert getattr(widget, "_status_worker") is None


def test_get_settings_reflects_form_and_strips_path(qtbot: QtBot, tmp_path: Path) -> None:
    """``get_settings`` reports the form's current values with the path stripped of surrounding whitespace.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    widget = _make_widget(qtbot, tmp_path)
    _attr(widget, "_path_input", QLineEdit).setText("  C:/tools/ghidra  ")
    _attr(widget, "_enabled_checkbox", QCheckBox).setChecked(False)
    _attr(widget, "_auto_install_checkbox", QCheckBox).setChecked(False)
    _attr(widget, "_timeout_spin", QSpinBox).setValue(200)

    assert widget.get_settings() == {
        "enabled": False,
        "path": "C:/tools/ghidra",
        "auto_install": False,
        "startup_timeout_seconds": 200,
    }


def test_save_settings_creates_file_and_round_trips(qtbot: QtBot, tmp_path: Path) -> None:
    """Saving creates the config directory and file, and a new widget reading it shows the saved values.

    Args:
        qtbot: pytest-qt bot used to close the widgets.
        tmp_path: Per-test temporary directory.
    """
    config_path = tmp_path / "nested" / "config" / "tools.json"
    widget = _make_widget(qtbot, tmp_path, config_path=config_path)
    _attr(widget, "_path_input", QLineEdit).setText(str(tmp_path / "saved-ghidra"))
    _attr(widget, "_enabled_checkbox", QCheckBox).setChecked(False)
    _attr(widget, "_timeout_spin", QSpinBox).setValue(77)

    widget.save_settings()

    expected = {"enabled": False, "path": str(tmp_path / "saved-ghidra"), "auto_install": True, "startup_timeout_seconds": 77}
    assert json.loads(config_path.read_text(encoding="utf-8")) == {"ghidra": expected}
    assert _make_widget(qtbot, tmp_path, config_path=config_path).get_settings() == expected


def test_save_settings_keeps_other_tools_entries(qtbot: QtBot, tmp_path: Path) -> None:
    """Saving one tool replaces only its own entry and keeps every other tool's stored settings.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    config_path = _write_tool_settings(tmp_path, {"x64dbg": {"path": "keep-me"}, "ghidra": {"path": "old"}})
    widget = _make_widget(qtbot, tmp_path, config_path=config_path)
    _attr(widget, "_path_input", QLineEdit).setText("new")

    widget.save_settings()

    saved = cast("dict[str, dict[str, object]]", json.loads(config_path.read_text(encoding="utf-8")))
    assert saved["x64dbg"] == {"path": "keep-me"}
    assert saved["ghidra"]["path"] == "new"
    assert list(saved) == ["x64dbg", "ghidra"]


def test_save_settings_replaces_corrupt_file(qtbot: QtBot, tmp_path: Path) -> None:
    """Saving over a corrupt ``tools.json`` discards the unreadable content and writes only this tool's settings.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
    """
    config_path = tmp_path / "tools.json"
    config_path.write_text("{this is not json", encoding="utf-8")
    widget = _make_widget(qtbot, tmp_path, config_path=config_path)

    widget.save_settings()

    assert json.loads(config_path.read_text(encoding="utf-8")) == {"ghidra": widget.get_settings()}


def test_save_settings_reports_unwritable_destination(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When the settings file cannot be opened for writing, the user gets a Save Error and nothing is replaced.

    Args:
        qtbot: pytest-qt bot used to close the widget.
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture that restores the message box.
    """
    warnings = _capture_dialog(monkeypatch, "warning")
    config_path = tmp_path / "tools.json"
    config_path.mkdir()
    widget = _make_widget(qtbot, tmp_path, config_path=config_path)

    widget.save_settings()

    assert len(warnings) == 1
    title, text = warnings[0]
    assert title == "Save Error"
    assert text.startswith("Failed to save settings: ")
    assert config_path.is_dir()


def test_capabilities_widget_marks_supported_and_unsupported_features(qtbot: QtBot) -> None:
    """Supported capabilities show a filled marker and unsupported ones an empty marker, with architectures and formats listed.

    Args:
        qtbot: pytest-qt bot used to close the widget.
    """
    widget = ToolCapabilitiesWidget()
    qtbot.addWidget(widget)
    labels = cast("dict[str, QLabel]", getattr(widget, "_cap_labels"))
    all_supported: dict[str, bool] = dict.fromkeys(
        (
            "supports_static_analysis",
            "supports_dynamic_analysis",
            "supports_decompilation",
            "supports_debugging",
            "supports_patching",
            "supports_scripting",
            "supports_memory_access",
        ),
        True,
    )
    widget.set_tool("Everything", all_supported, ["x86"], ["PE"])
    assert {cap_id: label.text() for cap_id, label in labels.items()} == dict.fromkeys(labels, "\u25cf")

    widget.set_tool("Demo", {"supports_debugging": True, "supports_patching": False}, ["x86", "ARM"], [])

    assert _attr(widget, "_name_label", QLabel).text() == "Demo"
    assert labels["debugging"].text() == "\u25cf"
    assert labels["patching"].text() == "\u25cb"
    assert labels["static_analysis"].text() == "\u25cb"
    assert labels["patching"].property("muted") == "true"
    assert _attr(widget, "_arch_label", QLabel).text() == "x86, ARM"
    assert _attr(widget, "_fmt_label", QLabel).text() == "--"


def test_capabilities_widget_tolerates_missing_capability_label(qtbot: QtBot) -> None:
    """A capability whose label is absent is skipped while the others still update.

    Args:
        qtbot: pytest-qt bot used to close the widget.
    """
    widget = ToolCapabilitiesWidget()
    qtbot.addWidget(widget)
    labels = cast("dict[str, QLabel]", getattr(widget, "_cap_labels"))
    del labels["patching"]

    widget.set_tool("Demo", {"supports_scripting": True, "supports_patching": True}, [], [])

    assert labels["scripting"].text() == "\u25cf"
    assert "patching" not in labels
    assert _attr(widget, "_arch_label", QLabel).text() == "--"


def test_status_dialog_refresh_renders_every_tool_from_real_workers(qtbot: QtBot, tmp_path: Path, state_dir: Path) -> None:
    """Opening the dialog without a snapshot runs a real worker per tool and renders each tool's own result.

    Args:
        qtbot: pytest-qt bot used to close the dialog and wait for the workers' results.
        tmp_path: Per-test temporary directory.
        state_dir: Configuration directory holding the saved tool paths.
    """
    ghidra_root = tmp_path / "ghidra-install"
    _make_layout(ghidra_root, ("ghidra_11.2/support/analyzeHeadless.bat",))
    x64dbg_root = tmp_path / "x64dbg-install"
    _make_layout(x64dbg_root, ("release/x64/x64dbg.exe",))
    cutter_root = tmp_path / "cutter-install"
    _make_layout(cutter_root, ("cutter.exe",))
    _ = _write_tool_settings(
        state_dir,
        {"ghidra": {"path": str(ghidra_root)}, "x64dbg": {"path": str(x64dbg_root)}, "cutter": {"path": str(cutter_root)}},
    )

    dialog = ToolStatusDialog()
    qtbot.addWidget(dialog)
    refresh = _attr(dialog, "_refresh_btn", QPushButton)
    assert not refresh.isEnabled()
    rows = _refresh_and_collect(qtbot, dialog)

    assert len(rows) == 6
    assert rows[0] == "\u2713  Ghidra - Ghidra installed"
    assert rows[1] == "\u2713  x64dbg - x64dbg installed"
    assert rows[2].startswith("\u2713  Frida - Frida ")
    assert rows[2].endswith(" available")
    assert rows[3] == "\u2713  Cutter - Cutter installed"
    assert rows[4:] == [f"\u2713  Process Control - {_BUILTIN_STATUS}", f"\u2713  Binary Operations - {_BUILTIN_STATUS}"]
    assert getattr(dialog, "_status_workers") == []
    assert _attr(dialog, "_status_list", QListWidget).currentRow() == 0
    statuses = cast("dict[str, tuple[bool, str]]", getattr(dialog, "_tool_statuses"))
    assert set(statuses) == set(_TOOL_IDS)
    assert statuses["ghidra"] == (True, "Ghidra installed")


@pytest.mark.spawns_process
@pytest.mark.usefixtures("empty_path")
def test_status_dialog_refresh_marks_unavailable_tools(qtbot: QtBot, tmp_path: Path, state_dir: Path) -> None:
    """Tools that are unconfigured, missing or without their executable render with the unavailable marker and the reason.

    Args:
        qtbot: pytest-qt bot used to close the dialog and wait for the workers' results.
        tmp_path: Per-test temporary directory.
        state_dir: Configuration directory holding the saved tool paths.
    """
    cutter_root = tmp_path / "cutter-install"
    cutter_root.mkdir()
    _ = _write_tool_settings(state_dir, {"x64dbg": {"path": str(tmp_path / "absent")}, "cutter": {"path": str(cutter_root)}})

    dialog = ToolStatusDialog()
    qtbot.addWidget(dialog)
    rows = _refresh_and_collect(qtbot, dialog)

    assert rows[0] == "\u2717  Ghidra - Path not configured"
    assert rows[1] == "\u2717  x64dbg - Path does not exist"
    assert rows[3] == "\u2717  Cutter - Cutter executable not found"
    assert rows[4] == f"\u2713  Process Control - {_BUILTIN_STATUS}"
    assert rows[5] == f"\u2713  Binary Operations - {_BUILTIN_STATUS}"
    ghidra_row = _attr(dialog, "_status_list", QListWidget).item(0)
    assert ghidra_row is not None
    assert ghidra_row.toolTip() == "Ghidra - Path not configured"


@pytest.mark.usefixtures("state_dir")
def test_status_dialog_configure_opens_settings_dialog_then_refreshes(qtbot: QtBot) -> None:
    """Configure opens the tool settings dialog, and once it closes the status list is refreshed with fresh workers.

    The settings dialog's own modal loop is closed by a timer, standing in for the user pressing Cancel.

    Args:
        qtbot: pytest-qt bot used to close the dialog and wait for the workers' results.
    """
    dialog = _make_status_dialog(qtbot, _prefetched())
    refresh = _attr(dialog, "_refresh_btn", QPushButton)
    assert refresh.isEnabled()

    seen: list[tuple[str, int]] = []

    def _cancel_settings_dialog() -> None:
        """Reject the settings dialog once it is the active modal window, recording what was closed."""
        modal = QApplication.activeModalWidget()
        if isinstance(modal, ToolConfigDialog):
            modal.reject()
            seen.append((modal.windowTitle(), modal.result()))

    timer = QTimer()
    timer.setInterval(5)
    _ = timer.timeout.connect(_cancel_settings_dialog)
    timer.start()
    try:
        _ = _call(dialog, "_on_configure")
    finally:
        timer.stop()

    assert seen == [("Tool Settings", QDialog.DialogCode.Rejected.value)]
    assert not refresh.isEnabled()
    rows = _refresh_and_collect(qtbot, dialog)
    assert rows[0] == "\u2717  Ghidra - Path not configured"
    assert rows[4] == f"\u2713  Process Control - {_BUILTIN_STATUS}"


def test_status_dialog_configure_without_selection_does_nothing(qtbot: QtBot) -> None:
    """Configure with an empty tool list opens nothing and starts no workers.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
    """
    dialog = _make_status_dialog(qtbot, _prefetched())
    _attr(dialog, "_status_list", QListWidget).clear()

    _ = _call(dialog, "_on_configure")

    assert dialog.findChildren(ToolConfigDialog) == []
    assert getattr(dialog, "_status_workers") == []


def test_status_dialog_loads_saved_settings(qtbot: QtBot, state_dir: Path) -> None:
    """The dialog reads every tool's saved settings from ``tools.json``.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        state_dir: Configuration directory the dialog is redirected to.
    """
    saved: dict[str, dict[str, object]] = {"ghidra": {"path": "C:/g", "enabled": True}, "frida": {"startup_timeout_seconds": 30}}
    _ = _write_tool_settings(state_dir, saved)
    dialog = _make_status_dialog(qtbot, _prefetched())

    assert _call(dialog, "_load_settings") == saved


def test_status_dialog_without_settings_file_loads_nothing(qtbot: QtBot, state_dir: Path) -> None:
    """With no ``tools.json`` the dialog has no saved settings.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        state_dir: Configuration directory the dialog is redirected to.
    """
    dialog = _make_status_dialog(qtbot, _prefetched())

    assert not (state_dir / "tools.json").exists()
    assert _call(dialog, "_load_settings") == {}


def test_status_dialog_ignores_corrupt_settings_file(qtbot: QtBot, state_dir: Path) -> None:
    """A corrupt ``tools.json`` is treated as no saved settings.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        state_dir: Configuration directory the dialog is redirected to.
    """
    state_dir.mkdir(parents=True)
    (state_dir / "tools.json").write_text("[1, 2", encoding="utf-8")
    dialog = _make_status_dialog(qtbot, _prefetched())

    assert _call(dialog, "_load_settings") == {}


def test_status_dialog_ignores_unreadable_settings_path(qtbot: QtBot, state_dir: Path) -> None:
    """A settings path the operating system cannot read as a file is treated as no saved settings.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
        state_dir: Configuration directory the dialog is redirected to.
    """
    (state_dir / "tools.json").mkdir(parents=True)
    dialog = _make_status_dialog(qtbot, _prefetched())

    assert _call(dialog, "_load_settings") == {}


def test_status_for_unlisted_tool_is_recorded_without_touching_rows(qtbot: QtBot) -> None:
    """A result for a tool that has no row is recorded, leaves every row alone and does not finish the refresh.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
    """
    dialog = _make_status_dialog(qtbot, {"ghidra": {"available": True, "path": None, "message": "Ghidra installed"}})
    status_list = _attr(dialog, "_status_list", QListWidget)
    before = _row_texts(status_list)
    refresh = _attr(dialog, "_refresh_btn", QPushButton)
    refresh.setEnabled(False)

    _ = _call(dialog, "_on_tool_status_received", "mystery", is_available=True, message="hello")

    assert _row_texts(status_list) == before
    statuses = cast("dict[str, tuple[bool, str]]", getattr(dialog, "_tool_statuses"))
    assert statuses["mystery"] == (True, "hello")
    assert not refresh.isEnabled()


def test_last_status_with_empty_list_reenables_refresh_and_drops_workers(qtbot: QtBot) -> None:
    """The sixth result re-enables Refresh and releases the workers, even when the list has no rows to select.

    Args:
        qtbot: pytest-qt bot used to close the dialog.
    """
    dialog = _make_status_dialog(qtbot, _prefetched(omit="binary"))
    status_list = _attr(dialog, "_status_list", QListWidget)
    status_list.clear()
    refresh = _attr(dialog, "_refresh_btn", QPushButton)
    refresh.setEnabled(False)
    workers = cast("list[ToolStatusCheckWorker]", getattr(dialog, "_status_workers"))
    workers.append(ToolStatusCheckWorker("binary", "", owner=dialog))

    _ = _call(dialog, "_on_tool_status_received", "binary", is_available=True, message=_BUILTIN_STATUS)

    assert refresh.isEnabled()
    assert workers == []
    assert status_list.count() == 0
    assert status_list.currentRow() == -1
