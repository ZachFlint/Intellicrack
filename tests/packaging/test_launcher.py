# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Falsifiable gates for the frozen ``Intellicrack.exe`` launcher.

These gates pin the launcher behaviours the installer audit flagged:

* A fatal startup failure must be reportable even when ``sys.stderr`` is
  ``None`` -- which it is in a frozen windowed process. The launcher must not
  raise ``AttributeError`` trying to write to a missing stream (the original
  bug, where ``return 1`` was unreachable dead code).
* ``runtime\\Scripts`` must never be placed on the child PATH: its pip
  console-script shims embed the absolute build-interpreter path, a hijack
  surface on a target where that path is user-writable.
* The child must be pointed at a per-user writable state directory under
  ``%LOCALAPPDATA%`` so credentials, config, logs, and data are never written
  under the read-only, world-readable install directory.

The launcher lives under ``packaging/launcher`` and is not an importable
package, so it is loaded from disk the same way ``test_hexbench_launcher`` loads
its bootstrapper.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest


if TYPE_CHECKING:
    from types import ModuleType

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_LAUNCHER_PATH: Final[Path] = _REPO_ROOT / "packaging" / "launcher" / "launcher.py"


def _load_launcher() -> ModuleType:
    """Load the ``launcher`` module directly from its source file.

    Returns:
        ModuleType: The imported ``launcher`` module.
    """
    spec = importlib.util.spec_from_file_location("intellicrack_launcher", _LAUNCHER_PATH)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load launcher from {_LAUNCHER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = _load_launcher()


class _RecordingMessageBox:
    """A stand-in for ``user32!MessageBoxW`` that records its calls."""

    def __init__(self) -> None:
        """Initialise the recorder with an empty call log."""
        self.calls: list[tuple[str, str, int]] = []
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, _hwnd: object, text: str, title: str, flags: int) -> int:
        """Record a MessageBox invocation.

        Args:
            _hwnd: Owner window handle (``None`` in these calls); unused.
            text: The message body.
            title: The dialog caption.
            flags: The MessageBox style flags.

        Returns:
            int: A constant ``1`` (IDOK), matching the real return contract.
        """
        self.calls.append((text, title, flags))
        return 1


class _FakeUser32:
    """A fake ``user32`` library exposing only ``MessageBoxW``."""

    def __init__(self, message_box: _RecordingMessageBox) -> None:
        """Store the recording MessageBox stand-in.

        Args:
            message_box: The recorder to expose as ``MessageBoxW``.
        """
        self.MessageBoxW = message_box


def _install_recording_message_box(monkeypatch: pytest.MonkeyPatch) -> _RecordingMessageBox:
    """Redirect the launcher's ``ctypes.WinDLL`` to a recording MessageBox.

    Args:
        monkeypatch: Pytest patching fixture.

    Returns:
        _RecordingMessageBox: The recorder that captures dialog calls.
    """
    recorder = _RecordingMessageBox()

    def _fake_windll(_name: str) -> _FakeUser32:
        return _FakeUser32(recorder)

    monkeypatch.setattr(launcher.ctypes, "WinDLL", _fake_windll)
    return recorder


def _make_fake_install(root: Path) -> Path:
    """Create a minimal staged install layout the launcher can resolve.

    Args:
        root: Directory to populate as a fake install root.

    Returns:
        Path: The install root that was created.
    """
    pythonw = root / "runtime" / "pythonw.exe"
    pythonw.parent.mkdir(parents=True, exist_ok=True)
    pythonw.write_bytes(b"MZ")
    (root / "app" / "src" / "intellicrack").mkdir(parents=True, exist_ok=True)
    return root


# --- Startup failure reporting (the dead-stderr bug) --------------------------


def test_report_error_survives_a_none_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reporting a failure with no ``sys.stderr`` must not raise, and must show a dialog.

    Args:
        monkeypatch: Pytest patching fixture.
    """
    recorder = _install_recording_message_box(monkeypatch)
    monkeypatch.setattr(launcher.sys, "stderr", None)

    launcher.report_error("runtime is missing")

    assert recorder.calls, "a windowed launcher with no stderr must surface the error in a dialog"
    text, _title, _flags = recorder.calls[0]
    assert "runtime is missing" in text


def test_report_error_writes_to_stderr_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """When a real stream exists the message is written to it as well.

    Args:
        monkeypatch: Pytest patching fixture.
    """
    _install_recording_message_box(monkeypatch)

    written: list[str] = []

    class _Stream:
        def write(self, text: str) -> int:
            written.append(text)
            return len(text)

        def flush(self) -> None:
            return None

    monkeypatch.setattr(launcher.sys, "stderr", _Stream())
    launcher.report_error("boom")

    assert "".join(written) == "boom\n"


# --- Child spawn configuration ------------------------------------------------


def test_creation_flags_detach_and_suppress_the_console() -> None:
    """The GUI child is detached with a new process group and no console window."""
    expected = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    assert launcher.creation_flags() == expected


def test_child_env_excludes_the_scripts_dir_from_path(tmp_path: Path) -> None:
    r"""``runtime\Scripts`` is never added to PATH even when it exists on disk.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
    """
    install = _make_fake_install(tmp_path / "app")
    (install / "runtime" / "Library" / "bin").mkdir(parents=True, exist_ok=True)
    (install / "runtime" / "Scripts").mkdir(parents=True, exist_ok=True)

    env = launcher.build_child_env(install)
    entries = env["PATH"].split(os.pathsep)

    assert str(install / "runtime") in entries
    assert str(install / "runtime" / "Library" / "bin") in entries
    assert str(install / "runtime" / "Scripts") not in entries, (
        "runtime\\Scripts hosts pip console-script shims that embed the build interpreter path; it must never be placed on the child PATH"
    )


def test_child_env_sets_state_dir_under_localappdata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The child is pointed at a per-user state dir under ``%LOCALAPPDATA%``.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Pytest patching fixture.
    """
    install = _make_fake_install(tmp_path / "app")
    local_app_data = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))

    env = launcher.build_child_env(install)

    expected = local_app_data / "Intellicrack"
    assert env["INTELLICRACK_STATE_DIR"] == str(expected)
    assert expected.is_dir(), "the launcher must create the per-user state directory"


def test_child_env_points_pythonpath_at_app_src(tmp_path: Path) -> None:
    """``PYTHONPATH`` leads with the staged ``app/src`` directory.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
    """
    install = _make_fake_install(tmp_path / "app")
    env = launcher.build_child_env(install)
    assert env["PYTHONPATH"].split(os.pathsep)[0] == str(install / "app" / "src")


def test_child_env_preserves_inherited_provider_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Inherited AI-provider credentials reach the child unchanged.

    The application authenticates providers from environment credentials, so the
    launcher must forward them verbatim. Reverting to a secret-stripping filter
    (which would break provider auth) drops these and fails here.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Pytest patching fixture.
    """
    install = _make_fake_install(tmp_path / "app")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-value")
    monkeypatch.setenv("HF_TOKEN", "hf-test-value")

    env = launcher.build_child_env(install)

    assert env["ANTHROPIC_API_KEY"] == "sk-ant-test-value"
    assert env["HF_TOKEN"] == "hf-test-value"


def test_child_env_introduces_no_new_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The launcher adds only non-sensitive variables, never a fresh secret.

    Every variable the child env adds or changes relative to ``os.environ`` must
    be one of the documented non-sensitive additions (the path, source, JDK, and
    state-directory variables). A launcher that injected a credential -- or any
    new key -- would appear here as an unexpected addition and fail.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Pytest patching fixture.
    """
    install = _make_fake_install(tmp_path / "app")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))

    baseline = dict(os.environ)
    env = launcher.build_child_env(install)

    allowed = {"PATH", "PYTHONPATH", "JAVA_HOME", "INTELLICRACK_STATE_DIR"}
    changed = {key for key in env if key not in baseline or env[key] != baseline.get(key)}
    unexpected = changed - allowed
    assert unexpected == set(), f"launcher changed or added variables outside its non-sensitive surface: {sorted(unexpected)}"


def test_child_env_does_not_mutate_the_process_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Assembling the child environment leaves ``os.environ`` untouched.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Pytest patching fixture.
    """
    install = _make_fake_install(tmp_path / "app")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    before = dict(os.environ)
    launcher.build_child_env(install)
    assert dict(os.environ) == before


# --- launch() routes failures through report_error ----------------------------


def test_launch_reports_and_fails_when_the_runtime_is_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing bundled ``pythonw.exe`` is reported and returns a non-zero code.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Pytest patching fixture.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    reported: list[str] = []

    def _record(message: str) -> None:
        reported.append(message)

    monkeypatch.setattr(launcher, "resolve_install_dir", lambda: empty)
    monkeypatch.setattr(launcher, "report_error", _record)

    def _fail_popen(*_args: object, **_kwargs: object) -> object:
        pytest.fail("launch must not spawn when the runtime is missing")

    monkeypatch.setattr(launcher.subprocess, "Popen", _fail_popen)

    assert launcher.launch([]) == 1
    assert reported, "a missing runtime must be reported"
    assert "runtime not found" in reported[0]


def test_launch_reports_and_fails_when_the_state_dir_cannot_be_created(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    r"""A state directory that cannot be created is reported, not raised at the user.

    ``build_child_env`` performs the one disk-touching step on the launch path:
    it creates ``%LOCALAPPDATA%\Intellicrack``. A file already occupying that
    name -- or a locked-down profile -- makes that ``mkdir`` raise, and the call
    used to sit outside every ``try``, so the exception escaped ``launch`` and
    the frozen windowed bootloader put a raw traceback on screen.

    The failure is produced for real rather than simulated: a *file* is placed
    where the directory must go, and the precondition below confirms
    ``build_child_env`` genuinely raises there before the routing is asserted.
    Removing the ``except OSError`` guard turns this red with the raw
    ``FileExistsError`` propagating out of ``launch``.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Pytest patching fixture.
    """
    install = _make_fake_install(tmp_path / "app")
    local_app_data = tmp_path / "LocalAppData"
    local_app_data.mkdir()
    (local_app_data / "Intellicrack").write_bytes(b"not a directory")
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setattr(launcher, "resolve_install_dir", lambda: install)

    with pytest.raises(OSError, match="Intellicrack"):
        launcher.build_child_env(install)

    reported: list[str] = []

    def _record(message: str) -> None:
        reported.append(message)

    monkeypatch.setattr(launcher, "report_error", _record)

    def _fail_popen(*_args: object, **_kwargs: object) -> object:
        pytest.fail("launch must not spawn a child when the environment could not be prepared")

    monkeypatch.setattr(launcher.subprocess, "Popen", _fail_popen)

    assert launcher.launch([]) == 1, "an unusable state directory must fail the launch, not spawn without one"
    assert reported, "the state-directory failure escaped launch() instead of reaching report_error"
    assert "environment" in reported[0].lower(), f"the reported message does not name the failure: {reported[0]!r}"


def test_launch_spawns_pythonw_detached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A well-formed install spawns ``pythonw.exe -m intellicrack`` detached.

    Args:
        tmp_path: Pytest temporary directory used to build a fake install.
        monkeypatch: Pytest patching fixture.
    """
    install = _make_fake_install(tmp_path / "app")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setattr(launcher, "resolve_install_dir", lambda: install)

    captured: dict[str, object] = {}

    def _fake_popen(command: list[str], **kwargs: object) -> object:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(launcher.subprocess, "Popen", _fake_popen)

    assert launcher.launch(["--flag"]) == 0
    command = captured["command"]
    assert isinstance(command, list)
    assert command[0] == str(install / "runtime" / "pythonw.exe")
    assert command[1:] == ["-m", "intellicrack", "--flag"]
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    expected = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    assert kwargs["creationflags"] == expected
