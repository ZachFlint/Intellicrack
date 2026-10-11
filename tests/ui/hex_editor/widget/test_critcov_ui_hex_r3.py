# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass coverage for the custom CRC source lookup and the tool status checker.

Two situations that earlier passes could not stage are driven with real operating-system behavior, each measured in the test container
before this file was written:

* A file the system refuses to describe. A deny entry on a directory, set with ``icacls`` and removed again directory-first in a
  ``finally``, makes ``Path.is_file()`` raise ``PermissionError`` for the file inside it.
* A Python without the ``frida`` package. A child interpreter marks the package unimportable before importing the product module and
  reports what the status worker and the status dialog show.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, cast

import intellicrack_hexcore
import pytest

import intellicrack
from intellicrack.ui.panels.hex_editor.hashing import HashingMixin


if TYPE_CHECKING:
    from collections.abc import Generator


pytestmark = pytest.mark.usefixtures("qapp")


_EVERYONE_DENY_LISTING: str = "*S-1-1-0:(OI)(CI)(RD,REA,RA)"
_CHILD_TIMEOUT_SECONDS: int = 240
_CHILD_MARKER: str = "CHILD_JSON "
_FRIDA_MISSING_MESSAGE: str = "Frida not installed (pip install frida)"
_BUILTIN_MESSAGE: str = "Available (built-in)"
_SAMPLE: bytes = bytes((index * 29 + 5) & 0xFF for index in range(256))

_FRIDA_BLOCKED_CHILD: str = r"""
import importlib.util
import json
import sys
import time

sys.modules["frida"] = None
out = {}
out["find_spec_frida"] = repr(importlib.util.find_spec("frida"))

from intellicrack.ui.tool_config import ToolStatusCheckWorker, ToolStatusDialog
from PyQt6.QtWidgets import QApplication

app = QApplication([])
worker = ToolStatusCheckWorker("frida", "")
emitted = []
worker.status_checked.connect(lambda *args: emitted.append(list(args)))
worker.run()
out["worker_emitted"] = emitted
out["check_builtin_frida"] = list(worker._check_builtin())
out["check_builtin_process"] = list(ToolStatusCheckWorker("process", "")._check_builtin())

dialog = ToolStatusDialog()
deadline = time.monotonic() + 90
while time.monotonic() < deadline and len(dialog._tool_statuses) < 6:
    app.processEvents()
    time.sleep(0.05)
out["dialog_statuses"] = {key: list(value) for key, value in dialog._tool_statuses.items()}
out["dialog_rows"] = [dialog._status_list.item(row).text() for row in range(dialog._status_list.count())]
out["dialog_refresh_enabled"] = dialog._refresh_btn.isEnabled()
dialog._status_list.setCurrentRow(2)
out["dialog_current_row"] = dialog._status_list.currentRow()
for status_worker in dialog._status_workers:
    status_worker.wait(10000)
dialog.close()
dialog.deleteLater()
app.processEvents()
print("CHILD_JSON " + json.dumps(out))
"""


class _CrcHost(HashingMixin):
    """Minimal host carrying the hashing mixin with the two attributes the CRC source lookup reads."""

    def __init__(self, document: object | None, file_path: Path | None) -> None:
        """Store the panel path and the document.

        Args:
            document: Document the mixin consults for its own file path, or ``None``.
            file_path: Path the panel reports as its own, or ``None``.
        """
        self.document = document
        self.file_path = file_path

    def resolve(self) -> str | None:
        """Resolve the file the custom CRC worker should stream.

        Returns:
            str | None: The chosen path, or ``None`` when the document should be streamed instead.
        """
        return self._resolve_custom_crc_file_path()


@contextmanager
def _deny_listing(directory: Path) -> Generator[None]:
    """Deny every account the right to read the attributes and contents of a directory and of what it holds.

    The deny entry is removed in a ``finally``, with the directory reset first, because resetting the file first can fail once the
    directory itself carries a deny entry.

    Args:
        directory: Directory to lock.

    Yields:
        None: While the deny entry is in force.
    """
    icacls = str(Path(os.environ["SYSTEMROOT"]) / "System32" / "icacls.exe")
    _ = subprocess.run([icacls, str(directory), "/deny", _EVERYONE_DENY_LISTING], check=True, capture_output=True)
    try:
        yield
    finally:
        _ = subprocess.run([icacls, str(directory), "/reset", "/t", "/c"], check=False, capture_output=True)


@pytest.mark.spawns_process
def test_custom_crc_source_is_none_when_the_panel_file_cannot_be_examined(tmp_path: Path) -> None:
    """A panel file the system refuses to describe is not offered to the streaming CRC worker.

    The same path resolves to itself before the deny entry is set, so the refusal is what removes it.

    Args:
        tmp_path: Per-test temporary directory.
    """
    locked = tmp_path / "locked"
    locked.mkdir()
    panel_file = locked / "crc.bin"
    panel_file.write_bytes(_SAMPLE)
    host = _CrcHost(None, panel_file)
    assert host.resolve() == str(panel_file)

    with _deny_listing(locked):
        assert host.resolve() is None

    assert host.resolve() == str(panel_file)


@pytest.mark.spawns_process
def test_custom_crc_source_falls_through_to_the_document_file_after_a_refused_panel_file(tmp_path: Path) -> None:
    """When the panel file cannot be examined the lookup moves on and returns the document's own file.

    Args:
        tmp_path: Per-test temporary directory.
    """
    locked = tmp_path / "locked"
    locked.mkdir()
    panel_file = locked / "crc.bin"
    panel_file.write_bytes(_SAMPLE)
    backing = tmp_path / "backing.bin"
    backing.write_bytes(_SAMPLE[::-1])
    document = intellicrack_hexcore.HexDocument.open(str(backing))
    try:
        host = _CrcHost(document, panel_file)
        assert host.resolve() == str(panel_file)

        with _deny_listing(locked):
            resolved = host.resolve()
    finally:
        document.close()

    assert resolved is not None
    assert Path(resolved).samefile(backing)


@pytest.mark.spawns_process
def test_status_checks_report_frida_missing_and_keep_the_dialog_usable(tmp_path: Path) -> None:
    """In an interpreter without the ``frida`` package the Frida check reports it missing and every other tool is still checked.

    Args:
        tmp_path: Per-test temporary directory, used as the user profile and state directory of the child.
    """
    package_file = intellicrack.__file__
    assert package_file is not None
    src_dir = str(Path(package_file).resolve().parent.parent)
    home = tmp_path / "home"
    state = home / "state"
    state.mkdir(parents=True)
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["USERPROFILE"] = str(home)
    env["INTELLICRACK_STATE_DIR"] = str(state)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [src_dir, env.get("PYTHONPATH", "")]))

    completed = subprocess.run(
        [sys.executable, "-c", _FRIDA_BLOCKED_CHILD],
        capture_output=True,
        text=True,
        timeout=_CHILD_TIMEOUT_SECONDS,
        check=False,
        env=env,
        cwd=str(tmp_path),
    )

    assert completed.returncode == 0, completed.stderr[-2000:]
    payloads = [line[len(_CHILD_MARKER) :] for line in completed.stdout.splitlines() if line.startswith(_CHILD_MARKER)]
    assert len(payloads) == 1
    result = cast("dict[str, object]", json.loads(payloads[0]))
    assert result["find_spec_frida"] == "None"
    assert result["worker_emitted"] == [["frida", False, _FRIDA_MISSING_MESSAGE]]
    assert result["check_builtin_frida"] == [False, _FRIDA_MISSING_MESSAGE]
    assert result["check_builtin_process"] == [True, _BUILTIN_MESSAGE]
    assert result["dialog_statuses"] == {
        "ghidra": [False, "Path not configured"],
        "x64dbg": [False, "Path not configured"],
        "frida": [False, _FRIDA_MISSING_MESSAGE],
        "cutter": [False, "Path not configured"],
        "process": [True, _BUILTIN_MESSAGE],
        "binary": [True, _BUILTIN_MESSAGE],
    }
    assert result["dialog_rows"] == [
        "✗  Ghidra - Path not configured",
        "✗  x64dbg - Path not configured",
        f"✗  Frida - {_FRIDA_MISSING_MESSAGE}",
        "✗  Cutter - Path not configured",
        f"✓  Process Control - {_BUILTIN_MESSAGE}",
        f"✓  Binary Operations - {_BUILTIN_MESSAGE}",
    ]
    assert result["dialog_refresh_enabled"] is True
    assert result["dialog_current_row"] == 2
