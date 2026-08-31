# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for x64dbg plugin deployment utilities.

The deployment function copies pre-built x64dbg plugin binaries into the
correct ``release/{arch}/plugins`` directory. A faithful deployment must place
the byte-for-byte identical binary for the matching architecture (a ``.dp64``
must be an AMD64 PE, a ``.dp32`` must be an I386 PE); a deployment that
corrupted the bytes or crossed the architectures would load the wrong plugin
into x64dbg. To gate that, the fixtures here build *real, valid* minimal PE
images with the correct ``IMAGE_FILE_MACHINE`` field, and the tests verify the
deployed file against an independent oracle (the ``pefile`` parser plus a
SHA-256 checksum) rather than merely asserting the copy returned ``True``.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import time
from typing import TYPE_CHECKING

import pefile
import pytest

from intellicrack.bridges.installer import (
    deploy_x64dbg_plugin,
    deploy_x64dbg_plugin_detailed,
)
from intellicrack.core.config import get_project_root


if TYPE_CHECKING:
    from pathlib import Path


_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_IMAGE_FILE_MACHINE_I386 = 0x14C
_PE32PLUS_MAGIC = 0x20B
_PE32_MAGIC = 0x10B
_DOS_HEADER_SIZE = 64
_E_LFANEW_OFFSET = 0x3C
_PE_SIGNATURE = b"PE\x00\x00"
_OPTIONAL_HEADER_SIZE = 0xE0
_FILE_CHARACTERISTICS = 0x0102 | 0x2000
_SUBSYSTEM_OFFSET = 68
_SUBSYSTEM_NATIVE = 1
_ENTRYPOINT_RVA_OFFSET = 16
_ENTRYPOINT_RVA = 0x1000
_IMAGEBASE64_OFFSET = 24
_IMAGEBASE64 = 0x140000000
_IMAGEBASE32_OFFSET = 28
_IMAGEBASE32 = 0x10000000
_NUM_RVA_OFFSET = 92
_NUM_RVA_AND_SIZES = 16
_SECTION_CHARACTERISTICS = 0x60000020
_IMAGE_PADDED_SIZE = 0x600


def _build_real_pe(machine: int) -> bytes:
    r"""Build a minimal but spec-valid PE image with the given machine type.

    The resulting bytes parse cleanly under ``pefile`` and carry a genuine
    DOS header, ``PE\0\0`` signature, COFF file header (with the requested
    ``IMAGE_FILE_MACHINE``), optional header, and a single ``.text`` section.
    This is a real binary, not a stub MZ prefix, so it exercises the real
    deployment path the way an actual ``.dp64``/``.dp32`` plugin would.

    Args:
        machine: ``IMAGE_FILE_MACHINE`` value (AMD64 or I386).

    Returns:
        bytes: A complete, ``pefile``-parseable PE image.
    """
    is_64 = machine == _IMAGE_FILE_MACHINE_AMD64
    mz = bytearray(_DOS_HEADER_SIZE)
    mz[:2] = b"MZ"
    struct.pack_into("<I", mz, _E_LFANEW_OFFSET, _DOS_HEADER_SIZE)

    coff = struct.pack(
        "<HHIIIHH",
        machine,
        1,
        0,
        0,
        0,
        _OPTIONAL_HEADER_SIZE,
        _FILE_CHARACTERISTICS,
    )

    opt = bytearray(_OPTIONAL_HEADER_SIZE)
    struct.pack_into("<H", opt, 0, _PE32PLUS_MAGIC if is_64 else _PE32_MAGIC)
    struct.pack_into("<I", opt, _ENTRYPOINT_RVA_OFFSET, _ENTRYPOINT_RVA)
    if is_64:
        struct.pack_into("<Q", opt, _IMAGEBASE64_OFFSET, _IMAGEBASE64)
    else:
        struct.pack_into("<I", opt, _IMAGEBASE32_OFFSET, _IMAGEBASE32)
    struct.pack_into("<H", opt, _SUBSYSTEM_OFFSET, _SUBSYSTEM_NATIVE)
    struct.pack_into("<I", opt, _NUM_RVA_OFFSET, _NUM_RVA_AND_SIZES)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        _ENTRYPOINT_RVA,
        _ENTRYPOINT_RVA,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        _SECTION_CHARACTERISTICS,
    )

    image = bytes(mz) + _PE_SIGNATURE + coff + bytes(opt) + section
    return image.ljust(_IMAGE_PADDED_SIZE, b"\x00")


def _assert_deployed_pe(target: Path, source: bytes, expected_machine: int) -> None:
    """Assert a deployed plugin is the byte-identical, correct-arch PE.

    Args:
        target: Path to the deployed plugin inside the x64dbg tree.
        source: Original source bytes the deployment copied from.
        expected_machine: ``IMAGE_FILE_MACHINE`` the deployed PE must declare.
    """
    assert target.is_file()
    deployed = target.read_bytes()
    assert hashlib.sha256(deployed).hexdigest() == hashlib.sha256(source).hexdigest()

    assert deployed[:2] == b"MZ"
    e_lfanew = int(struct.unpack_from("<I", deployed, _E_LFANEW_OFFSET)[0])
    assert deployed[e_lfanew : e_lfanew + 4] == _PE_SIGNATURE

    pe = pefile.PE(data=deployed, fast_load=True)
    try:
        assert pe.FILE_HEADER.Machine == expected_machine
    finally:
        pe.close()


DUMMY_PE = _build_real_pe(_IMAGE_FILE_MACHINE_AMD64)
DUMMY_PE_32 = _build_real_pe(_IMAGE_FILE_MACHINE_I386)
DUMMY_ALTERNATE = _build_real_pe(_IMAGE_FILE_MACHINE_AMD64) + b"\xff" * 16
DUMMY_PE_32_ALT = _build_real_pe(_IMAGE_FILE_MACHINE_I386) + b"\xff" * 16


def _make_x64dbg_tree(root: Path) -> Path:
    """Create a minimal x64dbg directory layout.

    Args:
        root: Parent directory for the x64dbg installation.

    Returns:
        Path: Path to the x64dbg root.
    """
    x64dbg = root / "x64dbg"
    (x64dbg / "release" / "x64" / "plugins").mkdir(parents=True)
    (x64dbg / "release" / "x32" / "plugins").mkdir(parents=True)
    return x64dbg


def _make_plugin_source(
    tools_dir: Path,
    filename: str,
    content: bytes,
    subdir: str = "bin",
) -> Path:
    """Write a fake plugin binary into the plugin source tree.

    Args:
        tools_dir: Source root directory that contains ``x64dbg-plugin/``.
        filename: Plugin filename (e.g. ``intellicrack_bridge_x64.dp64``).
        content: Binary content to write.
        subdir: Sub-directory within x64dbg-plugin.

    Returns:
        Path: Path to the written file.
    """
    plugin_dir = tools_dir / "x64dbg-plugin" / subdir
    plugin_dir.mkdir(parents=True, exist_ok=True)
    binary = plugin_dir / filename
    binary.write_bytes(content)
    return binary


class TestFindPluginSourceViaDeployment:
    """Indirect tests for plugin source discovery via deploy_x64dbg_plugin."""

    @staticmethod
    def test_finds_binary_in_bin_directory(tmp_path: Path) -> None:
        """Deploy succeeds when source is in bin/ directory.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE, "bin")

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True
        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        assert target.read_bytes() == DUMMY_PE

    @staticmethod
    def test_finds_binary_in_build_plugins(tmp_path: Path) -> None:
        """Deploy succeeds when source is in build/plugins/.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x32.dp32",
            DUMMY_PE_32,
            subdir="build/plugins",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True
        target = x64dbg / "release" / "x32" / "plugins" / "intellicrack_bridge_x32.dp32"
        assert target.read_bytes() == DUMMY_PE_32

    @staticmethod
    def test_finds_binary_in_build_release(tmp_path: Path) -> None:
        """Deploy succeeds when source is in build/Release/.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x64.dp64",
            DUMMY_PE,
            subdir="build/Release",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True

    @staticmethod
    def test_finds_binary_in_arch_specific_build(tmp_path: Path) -> None:
        """Deploy succeeds when source is in build_x64/plugins/.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x64.dp64",
            DUMMY_PE,
            subdir="build_x64/plugins",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True

    @staticmethod
    def test_finds_binary_in_arch_specific_release(tmp_path: Path) -> None:
        """Deploy succeeds when source is in build_x32/Release/.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x32.dp32",
            DUMMY_PE_32,
            subdir="build_x32/Release",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True

    @staticmethod
    def test_priority_bin_over_build(tmp_path: Path) -> None:
        """Prefer bin/ over build/plugins/ when both exist.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", b"\x01" * 64, "bin")
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x64.dp64",
            b"\x02" * 64,
            subdir="build/plugins",
        )

        deploy_x64dbg_plugin(x64dbg, tmp_path)

        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        assert target.read_bytes() == b"\x01" * 64

    @staticmethod
    def test_priority_bin_over_arch_build_x32(tmp_path: Path) -> None:
        """Prefer the committed bin/ x32 plugin over a stale build_x32 output.

        This gates the exact layout the repository ships: the current plugin
        lives in ``x64dbg-plugin/bin`` while a regenerable ``build_x32`` tree
        may still hold an older compile. Deployment must select the ``bin``
        binary (a valid I386 PE) and never the stale build-tree copy.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x32.dp32", DUMMY_PE_32, "bin")
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x32.dp32",
            DUMMY_PE_32_ALT,
            subdir="build_x32/Release",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True

        target = x64dbg / "release" / "x32" / "plugins" / "intellicrack_bridge_x32.dp32"
        _assert_deployed_pe(target, DUMMY_PE_32, _IMAGE_FILE_MACHINE_I386)
        assert target.read_bytes() != DUMMY_PE_32_ALT


class TestDeployX64dbgPlugin:
    """Tests for deploy_x64dbg_plugin."""

    @staticmethod
    def test_returns_false_when_plugin_dir_missing(tmp_path: Path) -> None:
        """Return False when x64dbg-plugin directory does not exist.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is False

    @staticmethod
    def test_returns_false_when_no_binaries_exist(tmp_path: Path) -> None:
        """Return False when plugin directory exists but has no binaries.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        (tmp_path / "x64dbg-plugin").mkdir()
        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is False

    @staticmethod
    def test_deploys_dp64_binary(tmp_path: Path) -> None:
        """Deploy a .dp64 binary to x64 plugins directory.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        _assert_deployed_pe(target, DUMMY_PE, _IMAGE_FILE_MACHINE_AMD64)

    @staticmethod
    def test_deploys_dp32_binary(tmp_path: Path) -> None:
        """Deploy a .dp32 binary to x32 plugins directory.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x32.dp32", DUMMY_PE_32)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        target = x64dbg / "release" / "x32" / "plugins" / "intellicrack_bridge_x32.dp32"
        _assert_deployed_pe(target, DUMMY_PE_32, _IMAGE_FILE_MACHINE_I386)

    @staticmethod
    def test_deploys_both_architectures_to_matching_arch_trees(tmp_path: Path) -> None:
        """Deploy both plugins, each landing as the correct-architecture PE.

        The x64 source must arrive in ``release/x64/plugins`` as an AMD64 PE and
        the x32 source in ``release/x32/plugins`` as an I386 PE, each
        byte-identical to its source. This catches a deployment that crossed the
        architectures or corrupted the bytes, which the previous existence-only
        assertion could not.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x32.dp32", DUMMY_PE_32)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        _assert_deployed_pe(
            x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64",
            DUMMY_PE,
            _IMAGE_FILE_MACHINE_AMD64,
        )
        _assert_deployed_pe(
            x64dbg / "release" / "x32" / "plugins" / "intellicrack_bridge_x32.dp32",
            DUMMY_PE_32,
            _IMAGE_FILE_MACHINE_I386,
        )

    @staticmethod
    def test_skips_copy_when_target_is_newer(tmp_path: Path) -> None:
        """Skip copy when the target file has a newer mtime than source.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"

        time.sleep(0.05)
        target.write_bytes(DUMMY_ALTERNATE)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        assert target.read_bytes() == DUMMY_ALTERNATE

    @staticmethod
    def test_overwrites_when_source_is_newer(tmp_path: Path) -> None:
        """Overwrite target when source has a newer mtime.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)

        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        target.write_bytes(DUMMY_ALTERNATE)

        time.sleep(0.05)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        assert target.read_bytes() == DUMMY_PE

    @staticmethod
    def test_creates_plugins_directory_if_missing(tmp_path: Path) -> None:
        """Create the plugins directory when it does not yet exist.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
        """
        x64dbg = tmp_path / "x64dbg"
        x64dbg.mkdir()
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        assert (x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64").is_file()

    @staticmethod
    def test_gracefully_handles_copy_failure(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Return False and log warning when copy raises OSError.

        Args:
            tmp_path: Pytest-provided temporary directory used to build a fake deployment tree.
            monkeypatch: Pytest monkeypatch fixture used to stub ``shutil.copy2`` with a failing replacement.
        """
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        def _fail(_src: object, _dst: object, **_kw: object) -> object:
            raise OSError

        monkeypatch.setattr(shutil, "copy2", _fail)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)
        assert result is False


class TestDefaultSourceRootResolution:
    """Gate the default ``source_root`` resolution against built binaries."""

    @staticmethod
    def test_deploys_built_binaries_from_src_by_default(tmp_path: Path) -> None:
        """Omitting ``source_root`` deploys the built ``src/x64dbg-plugin`` PEs.

        When ``deploy_x64dbg_plugin_detailed`` is called with no explicit
        source root, it must resolve the plugin source to
        ``<project_root>/src/x64dbg-plugin`` and copy the byte-identical,
        correct-architecture ``.dp64``/``.dp32`` binaries built there into
        the x64dbg tree. This fails if the default resolution regresses (wrong
        base directory), or if a built binary carries the wrong
        ``IMAGE_FILE_MACHINE``.

        The plugin binaries are compiled build artifacts (no longer tracked in
        git); CI builds them from the committed C++ source before running this
        suite. When neither architecture's binary is present the environment
        lacks the MSVC toolchain output, so the gate is skipped rather than
        asserting against an artifact that cannot exist here.

        Args:
            tmp_path: Pytest-provided temporary directory used to host a fake x64dbg tree.
        """
        plugin_bin = get_project_root() / "src" / "x64dbg-plugin" / "bin"
        source64 = plugin_bin / "intellicrack_bridge_x64.dp64"
        source32 = plugin_bin / "intellicrack_bridge_x32.dp32"
        if not (source64.is_file() and source32.is_file()):
            pytest.skip(
                "x64dbg bridge plugins not built at src/x64dbg-plugin/bin; "
                "build them from source with CMake (requires the MSVC "
                "toolchain) to exercise default source-root deployment",
            )

        x64dbg = _make_x64dbg_tree(tmp_path)

        result = deploy_x64dbg_plugin_detailed(x64dbg)

        assert result.success is True
        target64 = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        target32 = x64dbg / "release" / "x32" / "plugins" / "intellicrack_bridge_x32.dp32"
        _assert_deployed_pe(target64, source64.read_bytes(), _IMAGE_FILE_MACHINE_AMD64)
        _assert_deployed_pe(target32, source32.read_bytes(), _IMAGE_FILE_MACHINE_I386)
