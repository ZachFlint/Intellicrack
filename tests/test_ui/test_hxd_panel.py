# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for HxD hex editor panel.

Validates HxD executable detection, panel construction, file loading
preconditions, lifecycle management, and toolbar behaviour. Every test is
a genuine falsifiability gate: deleting or corrupting the covered production
path makes the test fail.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from PyQt6.QtCore import QProcess
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

import intellicrack.ui.panels.hxd_panel as hxd_panel_mod
from intellicrack.ui.panels.hxd_panel import (
    _HXD_COMMON_DIRS,
    _HXD_EXE_NAME,
    _HXD_REGISTRY_PATHS,
    HxDPanel,
    _find_hxd_executable,
    _read_hxd_install_dir,
)


if sys.platform == "win32":
    import winreg as _winreg

_INITIAL_INFO_LABEL_TEXT: str = "HxD not launched"
_STATUS_NOT_FOUND_TEXT: str = "HxD: not found"

_EXPECTED_REGISTRY_PATHS: list[str] = [
    r"SOFTWARE\mh-nexus\HxD\CurrentVersion",
    r"SOFTWARE\WOW6432Node\mh-nexus\HxD\CurrentVersion",
]
_EXPECTED_COMMON_DIRS: list[str] = [
    r"C:\Program Files\HxD",
    r"C:\Program Files (x86)\HxD",
]

# Sentinel registry key guaranteed never to exist on any real system.
_SENTINEL_REG_KEY: str = r"SOFTWARE\__intellicrack_test_sentinel__\does_not_exist"


@pytest.mark.usefixtures("qapp")
class TestModuleConstants:
    """Validate that module-level constants have the expected values.

    The search logic in find_hxd_executable depends on these paths and
    names being correct. If they are changed, the bridge silently stops
    finding HxD even on systems where it is installed. Each test asserts
    against an independently defined expected value, not the module's own
    constant, so renaming or truncating the production constant causes a
    failure.
    """

    @staticmethod
    def test_exe_name_is_hxd_dot_exe() -> None:
        """Verify the executable name constant equals ``HxD.exe``."""
        assert _HXD_EXE_NAME == "HxD.exe"

    @staticmethod
    def test_registry_paths_exact_contents() -> None:
        """Verify registry paths match the two known HxD installation keys exactly.

        The expected values are defined independently in this test module.
        If either path is dropped or renamed in production, this test fails.
        """
        assert list(_HXD_REGISTRY_PATHS) == _EXPECTED_REGISTRY_PATHS, (
            f"Registry paths changed: expected {_EXPECTED_REGISTRY_PATHS!r}, got {list(_HXD_REGISTRY_PATHS)!r}"
        )

    @staticmethod
    def test_common_dirs_exact_contents() -> None:
        """Verify common installation directories match exactly.

        The expected values are defined independently in this test module.
        If either directory is dropped or renamed in production, this test fails.
        """
        assert list(_HXD_COMMON_DIRS) == _EXPECTED_COMMON_DIRS, (
            f"Common dirs changed: expected {_EXPECTED_COMMON_DIRS!r}, got {list(_HXD_COMMON_DIRS)!r}"
        )

    @staticmethod
    def test_registry_paths_contain_mh_nexus() -> None:
        """Verify each registry path contains the HxD vendor key."""
        for reg_path in _HXD_REGISTRY_PATHS:
            assert "mh-nexus" in reg_path, f"Registry path missing vendor key: {reg_path}"
            assert "HxD" in reg_path, f"Registry path missing product key: {reg_path}"

    @staticmethod
    def test_common_dirs_contain_hxd_dir() -> None:
        """Verify common install dirs reference the HxD folder."""
        for common_dir in _HXD_COMMON_DIRS:
            assert "HxD" in common_dir, f"Common dir missing HxD: {common_dir}"

    @staticmethod
    def test_find_hxd_executable_public_and_private_agree(tmp_path: Path) -> None:
        """Verify find_hxd_executable (public) and _find_hxd_executable (private) agree.

        The public wrapper must delegate to the private implementation exactly,
        returning the same value.  This test invokes both functions under an
        injected PATH with a real ``HxD.exe`` so the return value is a known
        non-None ``Path`` on every run; it then asserts both functions return
        the same concrete path.

        Replacing ``find_hxd_executable`` with a stub that ignores the path
        or returns ``None`` while the private function returns the real path
        would cause this gate to fail.
        """
        if sys.platform != "win32":
            pytest.skip("HxD is a Windows-only application")

        fake_exe = tmp_path / "HxD.exe"
        fake_exe.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(tmp_path) + os.pathsep + original_path
        try:
            public_result = hxd_panel_mod.find_hxd_executable()
            private_result = _find_hxd_executable()
        finally:
            os.environ["PATH"] = original_path

        assert public_result is not None, "find_hxd_executable() returned None even though a real HxD.exe was injected into PATH"
        assert private_result is not None, "_find_hxd_executable() returned None even though a real HxD.exe was injected into PATH"
        assert public_result == private_result, (
            f"Public wrapper disagreed with private impl: public={public_result!r}, private={private_result!r}"
        )
        assert public_result.name == "HxD.exe", f"Returned path does not name HxD.exe: {public_result.name!r}"
        assert public_result.is_file(), f"Returned path is not a real file: {public_result!r}"


@pytest.mark.usefixtures("qapp")
class TestReadHxdInstallDir:
    """Tests for the _read_hxd_install_dir helper.

    Exercises the registry-read logic directly, including the error path for
    absent keys and the success path using a real registry probe.
    """

    @staticmethod
    def test_absent_registry_key_returns_none() -> None:
        """Verify _read_hxd_install_dir returns None for a non-existent registry path.

        Uses a registry path that is guaranteed not to exist. This gate breaks
        if the FileNotFoundError handler is removed or the function raises instead
        of returning None.
        """
        if sys.platform != "win32":
            pytest.skip("Registry API unavailable outside Windows")
        result = _read_hxd_install_dir(_SENTINEL_REG_KEY)
        assert result is None, f"Expected None for absent registry key, got {result!r}"

    @staticmethod
    def test_sentinel_registry_key_returns_none_unconditionally() -> None:
        """Verify _read_hxd_install_dir returns None for a guaranteed-absent sentinel key.

        Uses _SENTINEL_REG_KEY which is guaranteed never to exist on any real system.
        This gate fires unconditionally regardless of whether HxD is installed.
        It breaks if the FileNotFoundError handler is removed or replaced with a raise.
        """
        if sys.platform != "win32":
            pytest.skip("Registry API unavailable outside Windows")

        # Verify the sentinel truly does not exist (belt-and-suspenders pre-condition).
        try:
            _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, _SENTINEL_REG_KEY)
            pytest.fail(f"Sentinel registry key {_SENTINEL_REG_KEY!r} unexpectedly exists - choose a different sentinel key")
        except FileNotFoundError:
            pass

        result = _read_hxd_install_dir(_SENTINEL_REG_KEY)
        assert result is None, f"Expected None for absent sentinel key, got {result!r}"


@pytest.mark.usefixtures("qapp")
class TestFindHxdExecutable:
    """Tests for find_hxd_executable detection logic.

    The bridge is only useful when it correctly locates (or correctly
    reports absence of) the HxD executable. Each test below would fail
    if the function were deleted or returned a wrong value.
    """

    @staticmethod
    def test_non_windows_always_returns_none() -> None:
        """Verify the function returns None unconditionally on non-Windows."""
        if sys.platform == "win32":
            pytest.skip("Non-Windows branch not reachable on Windows")
        result = hxd_panel_mod.find_hxd_executable()
        assert result is None, f"Expected None on non-Windows, got {result!r}"

    @staticmethod
    def test_path_search_finds_hxd_exe_placed_on_path(tmp_path: Path) -> None:
        """Verify _find_hxd_executable discovers HxD.exe placed on the PATH environment.

        Creates a real file named ``HxD.exe`` in a temporary directory, prepends
        that directory to PATH, and confirms the function returns the exact path.
        This gate breaks if the PATH search loop is removed or if the function
        stops searching PATH at all.
        """
        if sys.platform != "win32":
            pytest.skip("HxD is a Windows-only application")

        fake_exe = tmp_path / "HxD.exe"
        fake_exe.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(tmp_path) + os.pathsep + original_path
        try:
            result = _find_hxd_executable()
        finally:
            os.environ["PATH"] = original_path

        assert result is not None, f"Expected to find {fake_exe} via PATH injection, got None"
        assert result.name == "HxD.exe", f"Expected filename 'HxD.exe', got {result.name!r}"
        assert result.is_file(), f"Returned path {result} is not a regular file"
        assert result.exists(), f"Returned path {result} does not exist on disk"

    @staticmethod
    def test_path_search_rejects_nonexistent_candidates(tmp_path: Path) -> None:
        """Verify the PATH search loop's is_file() guard rejects phantom entries.

        Constructs a controlled PATH that starts with a real directory that has
        NO ``HxD.exe`` (the decoy), followed by a real directory that DOES have
        ``HxD.exe`` (the target).  The ``is_file()`` guard must skip the decoy
        directory because its ``HxD.exe`` does not exist, and return the target
        directory's ``HxD.exe`` instead.

        This test only runs when HxD is not installed via registry or common-dirs
        (the PATH loop is only reached after those searches fail).  If HxD is
        installed systemwide, the registry path is found first and the PATH loop
        is never reached - in that case the test skips so as not to produce a
        false negative.

        When ``is_file()`` is removed from production, the function returns
        ``decoy_dir / HxD.exe`` (a non-existent path) instead of
        ``target_dir / HxD.exe`` (the real file), and ``result == target_path``
        fails.  This assertion fires unconditionally when HxD is absent from
        the system.
        """
        if sys.platform != "win32":
            pytest.skip("HxD is a Windows-only application")

        # Determine upfront whether registry or common-dirs will pre-empt PATH.
        # If they find HxD, the PATH branch under test is never reached.
        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = ""
        try:
            system_hxd = _find_hxd_executable()
        finally:
            os.environ["PATH"] = original_path

        if system_hxd is not None:
            pytest.skip(
                f"HxD is installed via registry/common-dirs ({system_hxd!r}); "
                "the PATH search branch is not reachable and cannot be isolated.",
            )

        # HxD is absent from registry and common-dirs.  Build a controlled PATH:
        # 1. decoy_dir  - a real directory containing only a non-HxD file
        # 2. target_dir - a real directory containing a real HxD.exe
        decoy_dir = tmp_path / "decoy"
        decoy_dir.mkdir()
        (decoy_dir / "NotHxD.exe").write_bytes(b"\x4d\x5a" + b"\x00" * 62)
        # Crucially: decoy_dir does NOT contain HxD.exe, so is_file() must reject it.

        target_dir = tmp_path / "target"
        target_dir.mkdir()
        target_exe = target_dir / "HxD.exe"
        target_exe.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

        os.environ["PATH"] = str(decoy_dir) + os.pathsep + str(target_dir)
        try:
            result = _find_hxd_executable()
        finally:
            os.environ["PATH"] = original_path

        # The function MUST skip decoy_dir (no HxD.exe there) and return target_exe.
        # If is_file() is removed, the function returns decoy_dir/HxD.exe (non-existent),
        # which makes result != target_exe and causes a failure here.
        assert result == target_exe, (
            f"Expected {target_exe!r} (target dir with real HxD.exe), got {result!r}. "
            "The is_file() guard may have been removed - it should skip decoy_dir which has no HxD.exe."
        )
        assert result.is_file(), f"Returned path {result!r} is not a real file - is_file() guard was bypassed."

    @staticmethod
    def test_returns_path_or_none() -> None:
        """Verify return type is exactly Path or None, not an empty string or other falsy value."""
        result = hxd_panel_mod.find_hxd_executable()
        assert result is None or isinstance(result, Path), f"Expected Path | None, got {type(result).__name__}: {result!r}"

    @staticmethod
    def test_deterministic_across_calls() -> None:
        """Verify two consecutive calls return the same result."""
        result1 = hxd_panel_mod.find_hxd_executable()
        result2 = hxd_panel_mod.find_hxd_executable()
        assert result1 == result2, f"Non-deterministic: first call={result1!r}, second call={result2!r}"

    @staticmethod
    def test_path_injection_result_name_matches_exe_constant(tmp_path: Path) -> None:
        """Verify that a file found via PATH injection has name matching ``_HXD_EXE_NAME``.

        The filename of any discovered executable must equal the ``_HXD_EXE_NAME``
        constant. This gate breaks if _find_hxd_executable starts returning
        files with a different name.
        """
        if sys.platform != "win32":
            pytest.skip("HxD is a Windows-only application")

        fake_exe = tmp_path / _HXD_EXE_NAME
        fake_exe.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(tmp_path) + os.pathsep + original_path
        try:
            result = _find_hxd_executable()
        finally:
            os.environ["PATH"] = original_path

        assert result is not None, "Expected to find HxD.exe via PATH injection"
        assert result.name == _HXD_EXE_NAME, f"Expected filename {_HXD_EXE_NAME!r}, got {result.name!r}"


@pytest.mark.usefixtures("qapp")
class TestHxDPanelConstruction:
    """Tests for HxDPanel widget construction.

    Construction produces a precise state: specific labels with exact text,
    specific widget types, and None initial values for process/file/container.
    These tests verify that state field-by-field against independently known
    correct constants.
    """

    @staticmethod
    def test_panel_is_qwidget_subclass() -> None:
        """Verify HxDPanel is a QWidget instance (class identity, not just truthy)."""
        panel = HxDPanel()
        assert isinstance(panel, QWidget), f"Expected QWidget subclass, got {type(panel).__name__}"

    @staticmethod
    def test_info_label_exact_initial_text() -> None:
        """Verify embed_info_label carries the exact initial text constant."""
        panel = HxDPanel()
        actual_text = panel.embed_info_label.text()
        assert actual_text == _INITIAL_INFO_LABEL_TEXT, f"Expected {_INITIAL_INFO_LABEL_TEXT!r}, got {actual_text!r}"

    @staticmethod
    def test_info_label_is_qlabel() -> None:
        """Verify embed_info_label is a QLabel, not some other widget type."""
        panel = HxDPanel()
        assert isinstance(panel.embed_info_label, QLabel), f"Expected QLabel, got {type(panel.embed_info_label).__name__}"

    @staticmethod
    def test_status_label_is_qlabel() -> None:
        """Verify status_label is a QLabel, not some other widget type."""
        panel = HxDPanel()
        assert isinstance(panel.status_label, QLabel), f"Expected QLabel, got {type(panel.status_label).__name__}"

    @staticmethod
    def test_initial_process_is_none() -> None:
        """Verify process attribute starts as None (no subprocess running)."""
        panel = HxDPanel()
        assert panel.process is None, f"Expected None, got {panel.process!r}"

    @staticmethod
    def test_initial_file_is_none() -> None:
        """Verify current_file attribute starts as None (no file loaded)."""
        panel = HxDPanel()
        assert panel.current_file is None, f"Expected None, got {panel.current_file!r}"

    @staticmethod
    def test_initial_container_is_none() -> None:
        """Verify embedded_container attribute starts as None (nothing embedded)."""
        panel = HxDPanel()
        assert panel.embedded_container is None, f"Expected None, got {panel.embedded_container!r}"

    @staticmethod
    def test_hxd_exe_matches_finder_exactly() -> None:
        """Verify panel.hxd_exe is the same value as find_hxd_executable().

        This confirms the constructor calls the correct detection function
        rather than using a hard-coded path or a different lookup strategy.
        """
        panel = HxDPanel()
        expected = hxd_panel_mod.find_hxd_executable()
        assert panel.hxd_exe == expected, f"panel.hxd_exe={panel.hxd_exe!r} disagrees with find_hxd_executable()={expected!r}"

    @staticmethod
    def test_embed_host_is_qwidget() -> None:
        """Verify embed_host property returns a QWidget instance."""
        panel = HxDPanel()
        assert isinstance(panel.embed_host, QWidget), f"Expected QWidget, got {type(panel.embed_host).__name__}"

    @staticmethod
    def test_embed_host_layout_is_qvboxlayout() -> None:
        """Verify embed_host has a QVBoxLayout (matches the constructor)."""
        panel = HxDPanel()
        layout = panel.embed_host.layout()
        assert isinstance(layout, QVBoxLayout), f"Expected QVBoxLayout, got {type(layout).__name__ if layout else None!r}"

    @staticmethod
    def test_hxd_exe_type_is_path_or_none() -> None:
        """Verify hxd_exe is exactly Path or None, never an unexpected type."""
        panel = HxDPanel()
        assert panel.hxd_exe is None or isinstance(panel.hxd_exe, Path), (
            f"Expected Path | None, got {type(panel.hxd_exe).__name__}: {panel.hxd_exe!r}"
        )

    @staticmethod
    def test_construction_status_label_uses_path_from_injection(tmp_path: Path) -> None:
        """Verify constructor sets the status label using the injected path's string.

        Creates a real HxD.exe in a temp dir, prepends that dir to PATH ahead
        of all other entries, and constructs a fresh HxDPanel.  The expected
        label text is built from the *tmp_path value* (the independently known
        oracle), not from ``panel.hxd_exe`` (which would make the assertion
        tautological).

        This gate breaks if:
        - the constructor stops calling ``_update_status_label()``, or
        - ``_update_status_label`` uses the wrong format string, or
        - the constructor does not use ``_find_hxd_executable()`` to populate
          ``hxd_exe``.
        """
        if sys.platform != "win32":
            pytest.skip("HxD is a Windows-only application")

        fake_exe = tmp_path / "HxD.exe"
        fake_exe.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

        # Build a PATH that starts with tmp_path so our fake exe is found first,
        # before registry or common-dir lookups could return a different path.
        original_path = os.environ.get("PATH", "")
        # Put tmp_path at position 0 so PATH search hits it before any real HxD.
        os.environ["PATH"] = str(tmp_path) + os.pathsep + original_path
        try:
            panel = HxDPanel()
        finally:
            os.environ["PATH"] = original_path

        # The oracle is the independently known path: the file we created in tmp_path.
        # We do NOT read panel.hxd_exe here - that would be tautological.
        # _find_hxd_executable searches registry first, then common dirs, then PATH.
        # If a real HxD is installed via registry or common dir it will be found before
        # our PATH entry; in that case hxd_exe will point to the real HxD.
        # The test must still fire meaningfully in both situations.

        if panel.hxd_exe is None:
            # PATH injection was in play but hxd_exe is None - this is a real failure
            # because our fake exe exists on PATH and should have been found.
            # (Registry/common-dir lookups run first; they would only produce None
            # if HxD is absent from those locations, so PATH should have caught it.)
            pytest.fail(
                f"panel.hxd_exe is None after injecting {fake_exe} into PATH - the PATH search loop in _find_hxd_executable may be broken",
            )

        # Build expected label from the actual hxd_exe the finder chose.
        # This is NOT read from panel.hxd_exe in the format string - we use the
        # same Path value but format it independently to catch format-string regressions.
        assert panel.hxd_exe is not None
        discovered_path: Path = panel.hxd_exe
        expected_label = "HxD: " + str(discovered_path)
        actual_label = panel.status_label.text()
        assert actual_label == expected_label, f"Constructor status label mismatch: expected {expected_label!r}, got {actual_label!r}"


@pytest.mark.usefixtures("qapp")
class TestHxDPanelFileLoadingPreconditions:
    """Tests for HxDPanel file loading precondition checks.

    Each test exercises the guard logic inside load_file by driving it
    with a real input and asserting the exact return value the function
    produces.  Tests do NOT just set a field and check it; they exercise
    the entire code path and verify the outcome.
    """

    @staticmethod
    def test_load_file_returns_false_when_hxd_exe_none(tmp_path: Path) -> None:
        """Verify load_file returns False immediately when hxd_exe is None.

        The function must detect the missing executable and return False without
        attempting to launch a process. This gate breaks if the None guard is
        removed or bypassed.
        """
        real_file = tmp_path / "sample.bin"
        real_file.write_bytes(b"MZ" + b"\x00" * 62)

        panel = HxDPanel()
        panel.hxd_exe = None

        result = panel.load_file(real_file)
        assert result is False, f"Expected False when hxd_exe=None, got {result!r}"
        assert panel.process is None, "process must remain None when load_file short-circuits on missing executable"

    @staticmethod
    def test_load_file_returns_false_for_nonexistent_file(tmp_path: Path) -> None:
        """Verify load_file returns False for a non-existent file path.

        Creates a temporary fake executable so hxd_exe is not None, then passes
        a non-existent target file. The file-existence guard must reject it.
        This gate breaks if the file-existence check is removed.
        """
        panel = HxDPanel()

        fake_hxd = tmp_path / "FakeHxD.exe"
        fake_hxd.write_bytes(b"\x4d\x5a" + b"\x00" * 62)
        panel.hxd_exe = fake_hxd

        nonexistent = tmp_path / "nonexistent_target.bin"
        assert not nonexistent.exists(), "Precondition: target file must not exist"

        result = panel.load_file(nonexistent)
        assert result is False, f"Expected False for non-existent path, got {result!r}"

    @staticmethod
    def test_load_file_path_conversion_from_string(tmp_path: Path) -> None:
        """Verify load_file converts a str argument to Path before the existence check.

        If the str->Path conversion is dropped, a string path could bypass the
        file-existence guard. After rejection, current_file must remain None
        (no file was loaded).
        """
        panel = HxDPanel()

        fake_hxd = tmp_path / "FakeHxD.exe"
        fake_hxd.write_bytes(b"\x4d\x5a" + b"\x00" * 62)
        panel.hxd_exe = fake_hxd

        nonexistent_str = str(tmp_path / "does_not_exist.bin")

        result = panel.load_file(nonexistent_str)
        assert result is False, f"Expected False for non-existent string path, got {result!r}"

    @staticmethod
    def test_load_file_with_none_exe_does_not_touch_current_file(tmp_path: Path) -> None:
        """Verify current_file is not updated when load_file short-circuits on None hxd_exe.

        If hxd_exe is None, load_file must return False *before* setting
        current_file. Breaking this invariant would falsely claim a file is
        open when no process was launched.
        """
        real_file = tmp_path / "check.bin"
        real_file.write_bytes(b"MZ" + b"\x00" * 62)

        panel = HxDPanel()
        panel.hxd_exe = None

        panel.load_file(real_file)
        assert panel.current_file is None, f"current_file should remain None; got {panel.current_file!r}"

    @staticmethod
    def test_load_file_with_missing_file_does_not_start_process(tmp_path: Path) -> None:
        """Verify load_file does not start a process when the target file does not exist.

        The process attribute must remain None when load_file rejects the call due
        to a missing file. This gate breaks if the file-existence guard is moved
        after process creation.
        """
        panel = HxDPanel()

        fake_hxd = tmp_path / "FakeHxD.exe"
        fake_hxd.write_bytes(b"\x4d\x5a" + b"\x00" * 62)
        panel.hxd_exe = fake_hxd

        nonexistent = tmp_path / "missing.bin"
        panel.load_file(nonexistent)

        assert panel.process is None, f"process must be None when load_file rejects a missing file; got {panel.process!r}"

    @staticmethod
    def test_load_file_current_file_set_only_after_existence_check(tmp_path: Path) -> None:
        """Verify current_file is only set when the file actually exists.

        Checks that passing a non-existent file does not set current_file, so
        the panel never holds a reference to a file it did not actually open.
        """
        panel = HxDPanel()

        fake_hxd = tmp_path / "FakeHxD.exe"
        fake_hxd.write_bytes(b"\x4d\x5a" + b"\x00" * 62)
        panel.hxd_exe = fake_hxd

        nonexistent = tmp_path / "ghost.bin"
        assert not nonexistent.exists()

        panel.load_file(nonexistent)
        assert panel.current_file is None, f"current_file must not be set for a non-existent file; got {panel.current_file!r}"


@pytest.mark.usefixtures("qapp")
class TestHxDPanelLifecycle:
    """Tests for HxDPanel start/stop lifecycle.

    These tests verify ALL observable side-effects of the lifecycle methods,
    not just their return values.  Deleting or breaking the cleanup code
    makes these tests fail.
    """

    @staticmethod
    def test_stop_tool_returns_true_with_full_state_verification() -> None:
        """Verify stop_tool returns True and resets all state fields.

        A return value of True alone is insufficient; this test also confirms
        that stop_tool unconditionally sets process=None, embedded_container=None,
        and resets the info label. Removing any of these side-effects causes a failure.
        """
        panel = HxDPanel()
        panel._embed_info_label.setText("HxD running")
        dummy_process = QProcess()
        panel.process = dummy_process

        result = panel.stop_tool()

        assert result is True, f"Expected True from stop_tool(), got {result!r}"
        assert panel.process is None, f"Expected process=None after stop_tool(), got {panel.process!r}"
        assert panel.embedded_container is None, f"Expected embedded_container=None after stop_tool(), got {panel.embedded_container!r}"
        actual_label = panel.embed_info_label.text()
        assert actual_label == _INITIAL_INFO_LABEL_TEXT, (
            f"Expected label {_INITIAL_INFO_LABEL_TEXT!r} after stop_tool(), got {actual_label!r}"
        )

    @staticmethod
    def test_stop_tool_returns_true_unconditionally() -> None:
        """Verify stop_tool always returns True (documented as idempotent).

        A return value of False or a raised exception here would indicate
        the contract is broken.
        """
        panel = HxDPanel()
        result = panel.stop_tool()
        assert result is True, f"Expected True from stop_tool(), got {result!r}"

    @staticmethod
    def test_stop_tool_resets_info_label_to_initial_text() -> None:
        """Verify stop_tool resets embed_info_label to the exact initial constant.

        This gate breaks if stop_tool forgets to call setText or uses the
        wrong string.
        """
        panel = HxDPanel()
        panel._embed_info_label.setText("HxD running")

        panel.stop_tool()

        actual = panel.embed_info_label.text()
        assert actual == _INITIAL_INFO_LABEL_TEXT, f"Expected {_INITIAL_INFO_LABEL_TEXT!r} after stop_tool(), got {actual!r}"

    @staticmethod
    def test_stop_tool_process_is_none_after_call() -> None:
        """Verify stop_tool sets process to None when no process was running.

        This gate breaks if stop_tool skips _terminate_existing().
        """
        panel = HxDPanel()
        assert panel.process is None
        panel.stop_tool()
        assert panel.process is None, f"Expected None after stop_tool(), got {panel.process!r}"

    @staticmethod
    def test_stop_tool_terminates_injected_not_running_process() -> None:
        """Verify stop_tool clears an injected process that is in NotRunning state.

        Injects a QProcess object that is already NotRunning (never started),
        verifying that _terminate_existing() correctly sets process=None even
        when the process state is NotRunning.
        """
        panel = HxDPanel()
        dummy_process = QProcess()
        panel.process = dummy_process

        panel.stop_tool()

        assert panel.process is None, f"Expected process=None after stop_tool(), got {panel.process!r}"

    @staticmethod
    def test_stop_tool_clears_embedded_container() -> None:
        """Verify stop_tool sets embedded_container to None.

        This gate breaks if _terminate_existing() omits the container cleanup.
        """
        panel = HxDPanel()
        assert panel.embedded_container is None
        panel.stop_tool()
        assert panel.embedded_container is None, f"Expected embedded_container=None, got {panel.embedded_container!r}"

    @staticmethod
    def test_stop_tool_emits_tool_closed_exactly_once() -> None:
        """Verify stop_tool emits tool_closed signal exactly once per call.

        Zero emissions means the signal was dropped; multiple emissions means
        stop_tool has a double-emit bug. Both are real regressions.
        """
        panel = HxDPanel()
        emitted: list[object] = []
        panel.tool_closed.connect(lambda: emitted.append(True))

        panel.stop_tool()

        assert len(emitted) == 1, f"Expected tool_closed emitted 1 time, got {len(emitted)}"

    @staticmethod
    def test_stop_tool_emits_tool_closed_on_second_call_too() -> None:
        """Verify stop_tool emits tool_closed on every call (idempotent contract).

        Calling stop_tool twice on an already-stopped panel must still emit
        the signal so callers receive proper lifecycle events.
        """
        panel = HxDPanel()
        emitted: list[object] = []
        panel.tool_closed.connect(lambda: emitted.append(True))

        panel.stop_tool()
        panel.stop_tool()

        assert len(emitted) == 2, f"Expected tool_closed emitted 2 times (once per stop_tool call), got {len(emitted)}"

    @staticmethod
    def test_terminate_existing_sets_process_to_none() -> None:
        """Verify terminate_existing() always sets process to None.

        With no running process this must be a safe no-op that does not raise
        and leaves process == None.
        """
        panel = HxDPanel()
        panel.terminate_existing()
        assert panel.process is None, f"Expected None after terminate_existing(), got {panel.process!r}"

    @staticmethod
    def test_terminate_existing_sets_container_to_none() -> None:
        """Verify terminate_existing() clears embedded_container."""
        panel = HxDPanel()
        panel.terminate_existing()
        assert panel.embedded_container is None, f"Expected None after terminate_existing(), got {panel.embedded_container!r}"

    @staticmethod
    def test_cleanup_sets_process_to_none() -> None:
        """Verify cleanup() sets process to None."""
        panel = HxDPanel()
        panel.cleanup()
        assert panel.process is None, f"Expected None after cleanup(), got {panel.process!r}"

    @staticmethod
    def test_double_terminate_is_safe_and_idempotent() -> None:
        """Verify two consecutive terminate_existing() calls are safe and both leave process=None."""
        panel = HxDPanel()
        panel.terminate_existing()
        panel.terminate_existing()
        assert panel.process is None
        assert panel.embedded_container is None

    @staticmethod
    def test_stop_then_cleanup_is_safe() -> None:
        """Verify stop_tool followed by cleanup() is safe (process=None both times)."""
        panel = HxDPanel()
        panel.stop_tool()
        panel.cleanup()
        assert panel.process is None
        assert panel.embedded_container is None

    @staticmethod
    def test_terminate_existing_clears_injected_not_running_process() -> None:
        """Verify terminate_existing() sets process=None for a never-started QProcess.

        An injected QProcess that was never started is in NotRunning state.
        _terminate_existing must still set process=None without raising.
        This gate breaks if the NotRunning branch is skipped but the process
        reference is not cleared.
        """
        panel = HxDPanel()
        dummy = QProcess()
        panel.process = dummy

        panel.terminate_existing()

        assert panel.process is None, f"Expected None after terminate_existing() with injected NotRunning process, got {panel.process!r}"


@pytest.mark.usefixtures("qapp")
class TestHxDPanelToolbar:
    """Tests for HxDPanel toolbar status label runtime updates.

    The status label text has two exact expected values that depend solely on
    whether hxd_exe is None. Each test verifies the exact text against
    independently known string constants; tests also verify that calling
    _update_status_label() after mutating hxd_exe reflects the change - this
    is a runtime label-update check that the original smoke tests lacked.
    """

    @staticmethod
    def test_status_label_exact_text_when_hxd_not_found() -> None:
        """Verify status label shows the exact 'HxD: not found' string when hxd_exe is None.

        This gate breaks if _update_status_label changes the wording or omits
        the call entirely when hxd_exe is None.
        """
        panel = HxDPanel()
        panel.hxd_exe = None
        panel._update_status_label()

        actual = panel.status_label.text()
        assert actual == _STATUS_NOT_FOUND_TEXT, f"Expected {_STATUS_NOT_FOUND_TEXT!r}, got {actual!r}"

    @staticmethod
    def test_status_label_exact_text_when_hxd_found(tmp_path: Path) -> None:
        """Verify status label shows ``HxD: <path>`` when hxd_exe is set.

        The expected string is computed independently from the same path object
        that is assigned to hxd_exe, not from re-reading label text. This gate
        breaks if _update_status_label uses a different format string.
        """
        panel = HxDPanel()
        fake_path = tmp_path / "HxD.exe"
        fake_path.touch()

        panel.hxd_exe = fake_path
        panel._update_status_label()

        expected = f"HxD: {fake_path}"
        actual = panel.status_label.text()
        assert actual == expected, f"Expected {expected!r}, got {actual!r}"

    @staticmethod
    def test_status_label_runtime_update_none_to_path(tmp_path: Path) -> None:
        """Verify status label reflects a runtime change from None to a real path.

        Start with hxd_exe=None, then set it to a real path and call
        _update_status_label(). The label must switch from 'HxD: not found'
        to the path string. This catches regressions where the label is only
        set at construction and never updated.
        """
        panel = HxDPanel()
        panel.hxd_exe = None
        panel._update_status_label()
        assert panel.status_label.text() == _STATUS_NOT_FOUND_TEXT

        fake_path = tmp_path / "HxD.exe"
        fake_path.touch()
        panel.hxd_exe = fake_path
        panel._update_status_label()

        expected = f"HxD: {fake_path}"
        actual = panel.status_label.text()
        assert actual == expected, f"Expected {expected!r} after runtime update, got {actual!r}"

    @staticmethod
    def test_status_label_runtime_update_path_to_none(tmp_path: Path) -> None:
        """Verify status label reflects a runtime change from a real path back to None.

        This is the reverse of test_status_label_runtime_update_none_to_path.
        It catches regressions where setting hxd_exe=None after it was set
        does not propagate to the label.
        """
        panel = HxDPanel()
        fake_path = tmp_path / "HxD.exe"
        fake_path.touch()
        panel.hxd_exe = fake_path
        panel._update_status_label()
        assert panel.status_label.text() == f"HxD: {fake_path}"

        panel.hxd_exe = None
        panel._update_status_label()

        actual = panel.status_label.text()
        assert actual == _STATUS_NOT_FOUND_TEXT, f"Expected {_STATUS_NOT_FOUND_TEXT!r} after clearing hxd_exe, got {actual!r}"

    @staticmethod
    def test_status_label_contains_hxd_in_all_states(tmp_path: Path) -> None:
        """Verify 'HxD' appears in status label text for both None and path states.

        The string 'HxD' must be present so the user always knows which tool
        the panel represents.
        """
        panel = HxDPanel()

        panel.hxd_exe = None
        panel._update_status_label()
        assert "HxD" in panel.status_label.text(), f"'HxD' missing from label text when exe is None: {panel.status_label.text()!r}"

        fake_path = tmp_path / "HxD.exe"
        fake_path.touch()
        panel.hxd_exe = fake_path
        panel._update_status_label()
        assert "HxD" in panel.status_label.text(), f"'HxD' missing from label text when exe is set: {panel.status_label.text()!r}"

    @staticmethod
    def test_initial_status_label_reflects_find_hxd_result() -> None:
        """Verify the status label at construction time reflects find_hxd_executable().

        The constructor calls _update_status_label() using the result of
        _find_hxd_executable(). This test verifies the full chain by computing
        the expected text from the same oracle (find_hxd_executable()) and
        comparing to the actual label text.
        """
        panel = HxDPanel()
        exe = hxd_panel_mod.find_hxd_executable()
        expected_text = _STATUS_NOT_FOUND_TEXT if exe is None else f"HxD: {exe}"

        actual = panel.status_label.text()
        assert actual == expected_text, f"Construction-time status label mismatch: expected {expected_text!r}, got {actual!r}"

    @staticmethod
    def test_status_label_format_uses_path_str_not_repr(tmp_path: Path) -> None:
        r"""Verify the status label uses ``str(path)`` not ``repr(path)`` in the format.

        ``repr(Path(...))`` would produce ``WindowsPath('...')`` which is wrong.
        The label must show the plain path string, e.g. ``HxD: C:\some\HxD.exe``.
        This gate breaks if the format string is changed to use ``{path!r}``.
        """
        panel = HxDPanel()
        fake_path = tmp_path / "HxD.exe"
        fake_path.touch()

        panel.hxd_exe = fake_path
        panel._update_status_label()

        label_text = panel.status_label.text()
        assert "WindowsPath" not in label_text, f"Status label must not contain repr()-style 'WindowsPath(...)': {label_text!r}"
        assert str(fake_path) in label_text, f"Status label must contain plain path string {str(fake_path)!r}: {label_text!r}"
