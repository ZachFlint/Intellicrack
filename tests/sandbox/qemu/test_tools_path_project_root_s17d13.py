# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D13: the bundled QEMU tools directory must follow the install.

``QEMUSandbox.TOOLS_PATH`` used to be the literal ``D:/Intellicrack/tools/qemu``
- one developer's checkout - so on every other installation ``_find_qemu`` never
looked at the bundled QEMU at all.

A plain equality assertion cannot gate this on a machine whose project root
happens to be ``D:/Intellicrack``: the hardcoded literal and the derived value
are identical there. These tests therefore re-execute the real ``qemu.py``
source as an independent module while ``get_project_root`` reports a different
root, and assert that ``TOOLS_PATH`` moved with it. A hardcoded literal stays
put and fails.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from intellicrack.core.config import get_project_root
from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from types import ModuleType

    import pytest


_qemu_source_file = qemu_module.__file__
assert _qemu_source_file is not None, "intellicrack.sandbox.qemu has no source file"
_QEMU_SOURCE: Final[Path] = Path(_qemu_source_file)
_PROBE_MODULE_NAME: Final[str] = "intellicrack_qemu_s17d13_probe"


def _load_qemu_copy(module_name: str) -> ModuleType:
    """Execute the real ``qemu.py`` source as a fresh, independent module.

    Re-running the module body recomputes every class-level constant, so
    ``TOOLS_PATH`` is resolved against whatever ``get_project_root`` returns at
    that moment. The copy is removed from ``sys.modules`` again so the real
    ``intellicrack.sandbox.qemu`` module stays untouched.

    Args:
        module_name: Name to register the executing copy under.

    Returns:
        ModuleType: The freshly executed module copy.
    """
    spec = importlib.util.spec_from_file_location(module_name, _QEMU_SOURCE)
    assert spec is not None, f"no import spec for {_QEMU_SOURCE}"
    loader = spec.loader
    assert loader is not None, f"no loader for {_QEMU_SOURCE}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        loader.exec_module(module)
    finally:
        del sys.modules[module_name]
    return module


def _tools_path_of(module: ModuleType) -> Path:
    """Read ``QEMUSandbox.TOOLS_PATH`` out of a freshly executed module copy.

    Args:
        module: Module copy produced by :func:`_load_qemu_copy`.

    Returns:
        Path: The tools directory that copy resolved when its class body ran.
    """
    sandbox_cls = vars(module)["QEMUSandbox"]
    return cast("Path", vars(sandbox_cls)["TOOLS_PATH"])


def _run_find_qemu(sandbox: QEMUSandbox) -> Path | None:
    """Run the sandbox's real QEMU discovery routine to completion.

    Args:
        sandbox: Sandbox whose discovery routine is exercised.

    Returns:
        Path | None: Resolved QEMU executable, or ``None`` when none is found.
    """
    finder: Callable[[], Coroutine[Any, Any, Path | None]] = getattr(sandbox, "_find_qemu")
    return asyncio.run(finder())


class TestToolsPathDerivesFromTheProjectRoot:
    """``TOOLS_PATH`` must be computed from the installed project root."""

    def test_tools_path_moves_with_the_project_root(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Relocating the project root relocates the bundled tools directory.

        This is the S17-D13 gate. With the hardcoded absolute path the copy
        resolves ``D:/Intellicrack/tools/qemu`` regardless of the root, which
        is not under ``tmp_path`` on any machine.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the reported project root.
        """
        relocated = tmp_path / "opt" / "Intellicrack"
        monkeypatch.setattr("intellicrack.core.config.get_project_root", lambda: relocated)

        tools_path = _tools_path_of(_load_qemu_copy(_PROBE_MODULE_NAME))

        assert tools_path == relocated / "tools" / "qemu", f"TOOLS_PATH ignored the relocated project root: {tools_path}"

    def test_tools_path_of_a_second_root_differs_from_the_first(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two different roots must yield two different tools directories.

        A constant answer - which is exactly what a hardcoded literal gives -
        makes the two resolutions identical.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the reported project root.
        """
        first_root = tmp_path / "install-a"
        monkeypatch.setattr("intellicrack.core.config.get_project_root", lambda: first_root)
        first = _tools_path_of(_load_qemu_copy(f"{_PROBE_MODULE_NAME}_a"))

        second_root = tmp_path / "install-b"
        monkeypatch.setattr("intellicrack.core.config.get_project_root", lambda: second_root)
        second = _tools_path_of(_load_qemu_copy(f"{_PROBE_MODULE_NAME}_b"))

        assert first != second, f"TOOLS_PATH is install-independent: both roots gave {first}"
        assert first.is_relative_to(first_root)
        assert second.is_relative_to(second_root)

    def test_installed_tools_path_matches_this_installation(self) -> None:
        """The live class attribute points inside this checkout's tools tree."""
        expected = get_project_root() / "tools" / "qemu"
        assert expected == QEMUSandbox.TOOLS_PATH


class TestFindQemuConsumesToolsPath:
    """``_find_qemu`` must keep working with the resolved tools directory."""

    def test_bundled_executable_is_preferred_when_present(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real executable under the tools directory is the chosen QEMU.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to point ``TOOLS_PATH`` at the fixture.
        """
        tools_dir = tmp_path / "tools" / "qemu"
        tools_dir.mkdir(parents=True)
        bundled = tools_dir / f"{QEMUSandbox.QEMU_EXE}.exe"
        bundled.write_bytes(b"MZ")
        monkeypatch.setattr(QEMUSandbox, "TOOLS_PATH", tools_dir)

        found = _run_find_qemu(QEMUSandbox(SandboxConfig(), QEMUConfig()))

        assert found == bundled

    def test_absent_tools_directory_is_skipped_without_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A missing tools directory contributes no candidate and never raises.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to point ``TOOLS_PATH`` at a missing dir.
        """
        missing = tmp_path / "not-installed" / "qemu"
        monkeypatch.setattr(QEMUSandbox, "TOOLS_PATH", missing)

        found = _run_find_qemu(QEMUSandbox(SandboxConfig(), QEMUConfig()))

        assert found is None or not found.is_relative_to(missing)
