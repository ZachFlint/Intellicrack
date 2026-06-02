# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for ``intellicrack.bridges.installer`` (SHARD 04).

These tests exercise the installer against real archives, the real
filesystem, real PE bytes, and real Python subprocesses rather than
faking the capability under test:

* ``install_tool`` runs the genuine ``_extract_zip`` + post-install
  executable search over a Cutter-shaped release archive; only the
  network boundary is stubbed. Both the missing-executable and
  present-executable layouts are covered (finding 04-F006).
* ``_extract_zip`` is called directly with a Zip-Slip ``../`` member, a
  Windows reserved-name member, and a legitimate PE-like member to
  verify the traversal guard, reserved-name guard, and a real
  round-trip extraction (finding 04-F008).
* ``probe_python_package`` runs a real subprocess against an installed
  package (present path) and an absent package (None path)
  (finding 04-F009, finding 04-F018 via the Frida registry entry).
* ``deploy_x64dbg_plugin_detailed`` deploys real plugin bytes into a
  realistic x64dbg tree and the per-arch result is asserted
  (finding 04-F010).
* ``find_tool_detailed`` discovers the builtin PROCESS tool and the
  Frida python-package tool with no mocked subprocess (finding 04-F012).
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
import threading
import zipfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.bridges.installer import (
    TOOL_REGISTRY,
    ToolInfo,
    ToolInstaller,
    deploy_x64dbg_plugin_detailed,
    pefile_available,
)
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


_PE_BYTES: Final[bytes] = b"MZ" + bytes(62)
_CUTTER_VERSION: Final[str] = "2.3.0"


def _build_zip(zip_path: Path, files: dict[str, bytes]) -> None:
    """Write a zip archive with the given member mapping.

    Args:
        zip_path: Path to write the zip file to.
        files: Mapping of archive-internal path to raw contents.
    """
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


@contextlib.contextmanager
def _serve_directory(directory: Path) -> Generator[str]:
    """Serve ``directory`` over real HTTP for the duration of the context.

    A genuine threaded HTTP server is started on an ephemeral loopback
    port so the installer's real ``_download_file`` streams the archive
    over a real socket. The server is shut down and joined on exit.

    Args:
        directory: Directory whose files are exposed for download.

    Yields:
        Generator[str]: Base URL (``http://127.0.0.1:<port>``) the files are served at.
    """
    handler = partial(SimpleHTTPRequestHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[0], server.server_address[1]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# 04-F008 - Zip-Slip and reserved-name guards, plus real extraction round-trip
# ---------------------------------------------------------------------------


class TestExtractZipGuards:
    """Coverage of the _extract_zip security guards via public extract_archive.

    The public ``extract_archive`` entry point invokes the protected
    ``_extract_zip`` internally, so driving the guards through it
    exercises the exact same Zip-Slip and reserved-name code without
    reaching into a protected member.
    """

    @staticmethod
    def test_rejects_path_traversal_member(tmp_path: Path) -> None:
        """A '../' member must raise ToolError before any file escapes dest.

        Args:
            tmp_path: Pytest temporary directory.
        """
        installer = ToolInstaller(tmp_path / "tools")
        archive = tmp_path / "evil.zip"
        _build_zip(archive, {"../../../evil.txt": b"pwn"})

        with pytest.raises(ToolError):
            asyncio.run(installer.extract_archive(archive, ToolName.CUTTER))

        # Nothing escaped the destination directory.
        assert not (tmp_path / "evil.txt").exists()
        assert not (tmp_path.parent / "evil.txt").exists()

    @staticmethod
    def test_rejects_windows_reserved_name(tmp_path: Path) -> None:
        """A member with a reserved 'CON' component must raise ToolError.

        Args:
            tmp_path: Pytest temporary directory.
        """
        installer = ToolInstaller(tmp_path / "tools")
        archive = tmp_path / "reserved.zip"
        _build_zip(archive, {"tools/CON/config.ini": b"data"})

        with pytest.raises(ToolError):
            asyncio.run(installer.extract_archive(archive, ToolName.CUTTER))

    @staticmethod
    def test_extracts_legitimate_pe_member(tmp_path: Path) -> None:
        """A safe PE-like member is extracted to the expected destination.

        Args:
            tmp_path: Pytest temporary directory.
        """
        installer = ToolInstaller(tmp_path / "tools")
        archive = tmp_path / "good.zip"
        _build_zip(archive, {"Cutter/cutter.exe": _PE_BYTES})

        result = asyncio.run(installer.extract_archive(archive, ToolName.CUTTER))

        assert result is not None
        extracted = result / "cutter.exe"
        assert extracted.is_file()
        assert extracted.read_bytes() == _PE_BYTES


# ---------------------------------------------------------------------------
# 04-F006 - install_tool runs real extract + post-install executable search
# ---------------------------------------------------------------------------


class TestInstallToolRealExtraction:
    """install_tool over a Cutter-shaped archive served by a real HTTP server.

    The Cutter registry's ``download_url`` is repointed at a loopback HTTP
    server (pure data substitution - the registry entry is a value, not the
    operation under test). Because the URL is non-GitHub, the real
    ``_get_latest_release_url`` returns it verbatim and the real
    ``_download_file`` streams the archive over a real socket, so the entire
    ``install_tool`` pipeline - URL resolution, chunked download, extraction,
    and post-install executable / version search - runs end to end with no
    method stubbed.
    """

    @staticmethod
    def _point_registry_at(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
        """Repoint the Cutter registry download URL at ``url``.

        Args:
            monkeypatch: Pytest fixture used to patch the registry value.
            url: Replacement download URL (must end in ``.zip``).
        """
        monkeypatch.setattr(TOOL_REGISTRY[ToolName.CUTTER], "download_url", url, raising=True)

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_missing_executable_reports_exact_failure(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An archive lacking cutter.exe yields the exact exe-search failure.

        The full real install pipeline runs over HTTP; the extracted tree
        contains no ``cutter.exe`` so the post-install executable search
        fails. The exact production error string is asserted.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to repoint the registry URL.
        """
        served = tmp_path / "served"
        served.mkdir()
        _build_zip(served / "cutter.zip", {"cutter-2.3.0/bin/readme.txt": b"no executable here"})

        installer = ToolInstaller(tmp_path / "tools")
        with _serve_directory(served) as base_url:
            TestInstallToolRealExtraction._point_registry_at(monkeypatch, f"{base_url}/cutter.zip")
            result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error == "no expected executable found after install: Cutter"
        assert result.version is None

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_present_executable_advances_to_exact_version_failure(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An archive with cutter.exe clears the exe search and fails on version.

        A real Cutter release unpacks into a single top-level directory
        with ``cutter.exe`` at its root. The post-install executable search
        must accept that real extracted layout; because the bundled PE
        carries no readable version resource, the install then fails at the
        version-verification stage. The exact production error string for
        that later stage is asserted, proving the exe search itself passed.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to repoint the registry URL.
        """
        served = tmp_path / "served"
        served.mkdir()
        _build_zip(
            served / "cutter.zip",
            {
                "Cutter-v2.3.0-Windows-x86_64/cutter.exe": _PE_BYTES,
                "Cutter-v2.3.0-Windows-x86_64/bin/rizin.exe": _PE_BYTES,
            },
        )

        installer = ToolInstaller(tmp_path / "tools")
        with _serve_directory(served) as base_url:
            TestInstallToolRealExtraction._point_registry_at(monkeypatch, f"{base_url}/cutter.zip")
            result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        # The exe search passed; failure is precisely the version stage.
        assert result.error == "post-install version verification failed: Cutter"
        assert result.path is not None
        assert (result.path / "cutter.exe").is_file()

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_download_http_404_reports_download_failure(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A 404 from the real server surfaces the exact download-failure error.

        The registry URL points at a path that the live HTTP server does
        not serve, so the real ``_download_file`` streaming path observes a
        404 and returns None, and ``install_tool`` reports the exact
        download-failure message. This exercises the genuine network error
        path rather than swallowing it.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to repoint the registry URL.
        """
        served = tmp_path / "served"
        served.mkdir()

        installer = ToolInstaller(tmp_path / "tools")
        with _serve_directory(served) as base_url:
            TestInstallToolRealExtraction._point_registry_at(monkeypatch, f"{base_url}/does-not-exist.zip")
            result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error == "Download failed for Cutter"
        assert result.path is None


# ---------------------------------------------------------------------------
# 04-F010 - deploy_x64dbg_plugin_detailed real per-arch deployment
# ---------------------------------------------------------------------------


class TestDeployDetailedRealTree:
    """deploy_x64dbg_plugin_detailed against a realistic x64dbg tree."""

    @staticmethod
    def test_deploys_x64_plugin_reports_success(tmp_path: Path) -> None:
        """A real .dp64 source is copied and reported as 'deployed'.

        Args:
            tmp_path: Pytest temporary directory.
        """
        x64dbg = tmp_path / "x64dbg"
        (x64dbg / "release" / "x64" / "plugins").mkdir(parents=True)
        (x64dbg / "release" / "x32" / "plugins").mkdir(parents=True)

        plugin_src_dir = tmp_path / "x64dbg_plugin" / "bin"
        plugin_src_dir.mkdir(parents=True)
        (plugin_src_dir / "intellicrack_bridge_x64.dp64").write_bytes(_PE_BYTES)

        result = deploy_x64dbg_plugin_detailed(x64dbg, tmp_path)

        x64_results = [arch for arch in result.per_arch if arch.arch == "x64"]
        assert len(x64_results) == 1
        assert x64_results[0].status == "deployed"
        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        assert target.is_file()
        assert target.read_bytes() == _PE_BYTES

        # The x32 arch has no source binary and is reported as missing_source.
        x32_results = [arch for arch in result.per_arch if arch.arch == "x32"]
        assert len(x32_results) == 1
        assert x32_results[0].status == "missing_source"

    @staticmethod
    def test_missing_plugin_dir_reports_failure(tmp_path: Path) -> None:
        """A missing x64dbg_plugin source tree yields an unsuccessful result.

        Args:
            tmp_path: Pytest temporary directory.
        """
        x64dbg = tmp_path / "x64dbg"
        (x64dbg / "release" / "x64" / "plugins").mkdir(parents=True)

        result = deploy_x64dbg_plugin_detailed(x64dbg, tmp_path)
        assert result.success is False


# ---------------------------------------------------------------------------
# 04-F012 - find_tool_detailed real builtin + python-package discovery
# ---------------------------------------------------------------------------


class TestFindToolDetailedRealHost:
    """find_tool_detailed against the real host environment."""

    @staticmethod
    def test_process_is_builtin_without_subprocess(tmp_path: Path) -> None:
        """PROCESS resolves to a builtin FoundTool with no subprocess.

        Args:
            tmp_path: Pytest temporary directory.
        """
        installer = ToolInstaller(tmp_path)
        found = asyncio.run(installer.find_tool_detailed(ToolName.PROCESS))
        assert found is not None
        assert found.kind == "builtin"
        assert found.path is None

    @staticmethod
    @pytest.mark.spawns_process
    def test_frida_python_package_discovery(tmp_path: Path) -> None:
        """FRIDA resolves to a python_package FoundTool or None, no mock.

        Both outcomes are valid depending on whether frida is installed in
        the active environment; the real ``_probe_python_package``
        subprocess path must run either way.

        Args:
            tmp_path: Pytest temporary directory.
        """
        installer = ToolInstaller(tmp_path)
        found = asyncio.run(installer.find_tool_detailed(ToolName.FRIDA))
        if found is None:
            pytest.skip("frida is not installed in the active environment")
        assert found.kind == "python_package"
        assert found.version is not None
        assert found.version.major >= 0


# ---------------------------------------------------------------------------
# 04-F009 / 04-F018 - probe_python_package real subprocess present/absent
# ---------------------------------------------------------------------------


class TestProbePythonPackageRealSubprocess:
    """probe_python_package against real Python subprocesses."""

    @staticmethod
    @pytest.mark.spawns_process
    def test_present_package_returns_version(tmp_path: Path) -> None:
        """A package installed in the env yields a parseable ToolVersion.

        Uses ``structlog`` (a hard dependency present in the pixi
        environment) so the real subprocess + version-parse path is
        validated end-to-end.

        Args:
            tmp_path: Pytest temporary directory.
        """
        installer = ToolInstaller(tmp_path)
        info = ToolInfo(
            name=ToolName.FRIDA,
            display_name="structlog",
            version_command=[
                sys.executable,
                "-c",
                "import structlog; print(structlog.__version__)",
            ],
            kind="python_package",
        )
        version = asyncio.run(installer.probe_python_package(info))
        assert version is not None
        assert version.major >= 0
        assert version.raw

    @staticmethod
    @pytest.mark.spawns_process
    def test_absent_package_returns_none(tmp_path: Path) -> None:
        """An import that fails (nonzero rc) yields None, not an exception.

        Args:
            tmp_path: Pytest temporary directory.
        """
        installer = ToolInstaller(tmp_path)
        info = ToolInfo(
            name=ToolName.FRIDA,
            display_name="absent-package",
            version_command=[
                sys.executable,
                "-c",
                "import _nonexistent_pkg_xyz; print(_nonexistent_pkg_xyz.__version__)",
            ],
            kind="python_package",
        )
        version = asyncio.run(installer.probe_python_package(info))
        assert version is None

    @staticmethod
    @pytest.mark.spawns_process
    def test_real_frida_registry_probe(tmp_path: Path) -> None:
        """The real Frida registry entry probes via subprocess (04-F018).

        On a host with frida installed the returned version must match the
        frida package; otherwise None is returned. Either way the real
        pip-installed package import + version parse path runs with no
        ProcessManager mock.

        Args:
            tmp_path: Pytest temporary directory.
        """
        installer = ToolInstaller(tmp_path)
        info = TOOL_REGISTRY[ToolName.FRIDA]
        version = asyncio.run(installer.probe_python_package(info))
        if version is None:
            pytest.skip("frida is not installed in the active environment")
        frida = pytest.importorskip("frida", reason="frida import failed despite probe success")
        expected_major = int(str(frida.__version__).split(".", 1)[0])
        assert version.major == expected_major
        assert version.raw
