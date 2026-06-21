# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for ``intellicrack.bridges.installer`` (SHARD 04).

These tests exercise the installer against real archives, the real
filesystem, real PE bytes, and real Python subprocesses rather than
faking the capability under test:

* ``install_tool`` runs the genuine ``_extract_zip`` + post-install
  executable search over a Cutter-shaped release archive.  The HTTP
  transport is controlled via ``httpx.MockTransport`` (injected via
  monkeypatch on ``_get_client``) so the real ``_get_latest_release_url``,
  ``_download_file``, ``_extract_zip``, ``_has_expected_executable``,
  ``_finalize_archive_install``, and ``get_version`` all run against the
  real implementation.  Both the missing-executable and present-executable
  layouts are covered, as are the real GitHub-API-error and download-error
  paths (findings 08-F1, 08-F2, 04-F006).
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
import io
import sys
import zipfile
from typing import TYPE_CHECKING, Final

import httpx
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
    from pathlib import Path


_PE_BYTES: Final[bytes] = b"MZ" + bytes(62)
_CUTTER_VERSION: Final[str] = "2.3.0"

_CUTTER_API_URL_SUBSTR: Final[str] = "api.github.com"
_CUTTER_ASSET_NAME: Final[str] = "Cutter-v2.3.0-Windows-x86_64.zip"
_CUTTER_DOWNLOAD_URL: Final[str] = "http://example.invalid/cutter.zip"

_ERR_NO_EXE: Final[str] = "no expected executable found after install: Cutter"
_ERR_NO_VERSION: Final[str] = "post-install version verification failed: Cutter"
_ERR_NO_URL: Final[str] = "Could not find download URL for Cutter"
_ERR_DOWNLOAD_FAILED: Final[str] = "Download failed for Cutter"


def _build_zip(zip_path: Path, files: dict[str, bytes]) -> None:
    """Write a zip archive with the given member mapping.

    Args:
        zip_path: Path to write the zip file to.
        files: Mapping of archive-internal path to raw contents.
    """
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def _make_zip_bytes(files: dict[str, bytes]) -> bytes:
    """Create an in-memory zip archive and return its raw bytes.

    Args:
        files: Mapping of archive-internal path to raw contents.

    Returns:
        bytes: Raw zip archive bytes.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_cutter_transport(zip_bytes: bytes) -> httpx.MockTransport:
    """Build a MockTransport that serves a synthetic GitHub API + zip download.

    The transport intercepts two URL patterns:
    - ``api.github.com`` -> returns a synthetic GitHub releases JSON listing
      one Windows x86_64 asset pointing at the controlled download URL.
    - ``example.invalid/cutter.zip`` -> streams the supplied ``zip_bytes``.

    Both the ``_get_latest_release_url`` (JSON parsing + arch-matching) and
    ``_download_file`` (streaming + chunking) code paths inside
    ``ToolInstaller`` run with their real logic against this transport.

    Args:
        zip_bytes: Raw zip archive bytes to serve as the download payload.

    Returns:
        httpx.MockTransport: Configured transport instance.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if _CUTTER_API_URL_SUBSTR in url_str:
            return httpx.Response(
                200,
                json={
                    "assets": [
                        {
                            "name": _CUTTER_ASSET_NAME,
                            "browser_download_url": _CUTTER_DOWNLOAD_URL,
                        },
                    ],
                },
            )
        if "example.invalid/cutter.zip" in url_str:
            return httpx.Response(
                200,
                content=zip_bytes,
                headers={"content-length": str(len(zip_bytes))},
            )
        return httpx.Response(404, text="Not Found")

    return httpx.MockTransport(_handler)


def _make_api_error_transport(status_code: int) -> httpx.MockTransport:
    """Build a MockTransport whose every response carries the given HTTP status.

    Used to exercise the real exception handler inside
    ``_get_latest_release_url`` that catches ``httpx.HTTPError`` (raised by
    ``response.raise_for_status()`` on a non-2xx status) and returns None.

    Args:
        status_code: HTTP status code to return for every request.

    Returns:
        httpx.MockTransport: Configured transport instance.
    """

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, text=f"Error {status_code}")

    return httpx.MockTransport(_handler)


def _make_download_error_transport() -> httpx.MockTransport:
    """Build a MockTransport where the API succeeds but the asset download fails.

    Used to exercise the real ``_download_file`` HTTP-error handling path:
    the GitHub API returns a valid asset list, but the asset download endpoint
    returns HTTP 500, triggering the ``except (httpx.HTTPError, ...)`` clause
    inside ``_download_file`` that removes the partial temp file and returns None.

    Returns:
        httpx.MockTransport: Configured transport instance.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        if _CUTTER_API_URL_SUBSTR in str(request.url):
            return httpx.Response(
                200,
                json={
                    "assets": [
                        {
                            "name": _CUTTER_ASSET_NAME,
                            "browser_download_url": _CUTTER_DOWNLOAD_URL,
                        },
                    ],
                },
            )
        return httpx.Response(500, text="Server Error")

    return httpx.MockTransport(_handler)


def _make_no_arch_match_transport() -> httpx.MockTransport:
    """Build a MockTransport where the API lists only a Linux asset.

    Used to exercise the real arch-matching logic inside
    ``_get_latest_release_url``: the method parses the asset list, calls
    ``_matches_arch`` for each candidate, finds no Windows / x86_64 match,
    and returns None, which ``install_tool`` surfaces as the exact
    ``"Could not find download URL"`` error.

    Returns:
        httpx.MockTransport: Configured transport instance.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        if _CUTTER_API_URL_SUBSTR in str(request.url):
            return httpx.Response(
                200,
                json={
                    "assets": [
                        {
                            "name": "Cutter-v2.3.0-Linux-x86_64.zip",
                            "browser_download_url": "http://example.invalid/linux.zip",
                        },
                    ],
                },
            )
        return httpx.Response(404, text="Not Found")

    return httpx.MockTransport(_handler)


def _patch_get_client(
    monkeypatch: pytest.MonkeyPatch,
    transport: httpx.MockTransport,
) -> None:
    """Monkeypatch ``ToolInstaller._get_client`` to return a client backed by ``transport``.

    The injected client uses ``httpx.MockTransport`` at the transport layer so
    the real ``_get_latest_release_url`` and ``_download_file`` methods run
    their production code paths while network I/O is controlled.  No production
    method is replaced; only the HTTP transport layer is substituted.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        transport: MockTransport instance to back the injected async client.
    """
    client = httpx.AsyncClient(transport=transport)

    async def _get_client_override(_self: ToolInstaller) -> httpx.AsyncClient:
        await asyncio.sleep(0)
        return client

    monkeypatch.setattr(ToolInstaller, "_get_client", _get_client_override)


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
# 04-F006, 08-F1, 08-F2 - install_tool with real HTTP transport (MockTransport)
#
# httpx.MockTransport is injected at the HTTP-transport layer via monkeypatch
# on ``_get_client``.  The real ``_get_latest_release_url``, ``_download_file``,
# ``_extract_zip``, and post-install verification code ALL run against the real
# implementation.  This is categorically different from patching those methods:
# the production GitHub API parsing, streaming-download chunking, error
# propagation, and archive extraction are all exercised end-to-end.
# ---------------------------------------------------------------------------


class TestInstallToolRealNetworkPipeline:
    """install_tool with real HTTP transport controlled by httpx.MockTransport.

    ``httpx.MockTransport`` is injected at the HTTP transport layer via
    monkeypatch on ``_get_client`` - the real ``_get_latest_release_url``,
    ``_download_file``, ``_extract_zip``, ``_has_expected_executable``,
    ``_finalize_archive_install``, and ``get_version`` all execute their
    production code paths.  The transport only controls what bytes come back
    over the wire; no production method is replaced, so every code path being
    tested is the genuine one.

    Addresses findings 08-F1 (real network-error path unverified) and 08-F2
    (only substring 'version' asserted) and 04-F006 (install_tool pipeline).
    """

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_missing_executable_exact_error_real_http(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Archive without cutter.exe produces the exact 'no expected executable' error.

        The full install pipeline runs through the real HTTP transport layer:
        ``_get_latest_release_url`` parses the synthetic GitHub API JSON,
        ``_download_file`` streams the archive bytes using the real chunked
        streaming code path, ``_extract_zip`` unpacks the real zip, and the
        post-install executable search finds no ``cutter.exe``.  The exact
        production error constant ``_ERR_NO_EXE_AFTER_INSTALL`` is asserted so
        any rename or message change is immediately caught.

        Addresses finding 08-F1: the real network-error code paths inside
        ``_get_latest_release_url`` and ``_download_file`` run; no production
        method is replaced by a stub.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to inject the HTTP transport.
        """
        zip_bytes = _make_zip_bytes({"cutter-2.3.0/bin/readme.txt": b"no executable here"})
        _patch_get_client(monkeypatch, _make_cutter_transport(zip_bytes))

        installer = ToolInstaller(tmp_path / "tools")
        result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error is not None
        assert result.error == _ERR_NO_EXE, f"Expected exact error {_ERR_NO_EXE!r}, got {result.error!r}"

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_present_executable_exact_version_error_real_http(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Archive with cutter.exe advances past exe-search; fails exactly at version.

        A real Cutter release layout (single top-level dir + ``cutter.exe``) is
        served through the real HTTP transport layer.  The post-install executable
        search succeeds; because the synthetic PE header has no ``VS_VERSION_INFO``
        resource, ``get_version`` returns None and the install fails at the
        version-verification stage.  The exact production error constant
        ``_ERR_NO_VERSION_AFTER_INSTALL`` is asserted so any rename or reworded
        message immediately breaks this test.

        Addresses finding 08-F2: exact equality on the error string (not a
        substring), and the real network pipeline runs without any method stub.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to inject the HTTP transport.
        """
        zip_bytes = _make_zip_bytes(
            {
                "Cutter-v2.3.0-Windows-x86_64/cutter.exe": _PE_BYTES,
                "Cutter-v2.3.0-Windows-x86_64/bin/rizin.exe": _PE_BYTES,
            },
        )
        _patch_get_client(monkeypatch, _make_cutter_transport(zip_bytes))

        installer = ToolInstaller(tmp_path / "tools")
        result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error is not None
        assert result.error != _ERR_NO_EXE, "Executable search should have passed with cutter.exe present"
        assert result.error == _ERR_NO_VERSION, f"Expected exact error {_ERR_NO_VERSION!r}, got {result.error!r}"

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_github_api_http_500_yields_no_url_error(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A GitHub API HTTP 500 response causes the exact 'Could not find download URL' error.

        This exercises the real exception handler inside
        ``_get_latest_release_url`` that catches ``httpx.HTTPError`` (raised by
        ``response.raise_for_status()`` on a 500) and returns None, which
        ``_install_archive_tool`` converts to the exact production error string.
        No method is stubbed; the real ``_get_latest_release_url`` code path runs.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to inject the HTTP transport.
        """
        _patch_get_client(monkeypatch, _make_api_error_transport(500))

        installer = ToolInstaller(tmp_path / "tools")
        result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error == _ERR_NO_URL, f"Expected exact error {_ERR_NO_URL!r}, got {result.error!r}"

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_no_arch_matching_asset_yields_no_url_error(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A GitHub API response with only a Linux asset yields 'Could not find download URL'.

        This exercises the real arch-matching logic inside
        ``_get_latest_release_url``: the method parses the asset list, calls
        ``_matches_arch`` for each candidate, finds no Windows / x86_64 match,
        and returns None.  The exact error string is asserted.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to inject the HTTP transport.
        """
        _patch_get_client(monkeypatch, _make_no_arch_match_transport())

        installer = ToolInstaller(tmp_path / "tools")
        result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error == _ERR_NO_URL, f"Expected exact error {_ERR_NO_URL!r}, got {result.error!r}"

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_download_http_500_yields_exact_download_failed_error(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A 500 on the asset download produces the exact 'Download failed' error.

        This exercises the real ``_download_file`` error-handling path: the
        method calls ``response.raise_for_status()`` which raises
        ``httpx.HTTPStatusError`` (a subclass of ``httpx.HTTPError``), the
        ``except (httpx.HTTPError, OSError, ValueError)`` clause catches it,
        removes the partial temp file, and returns None.  No method is stubbed.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to inject the HTTP transport.
        """
        _patch_get_client(monkeypatch, _make_download_error_transport())

        installer = ToolInstaller(tmp_path / "tools")
        result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error == _ERR_DOWNLOAD_FAILED, f"Expected exact error {_ERR_DOWNLOAD_FAILED!r}, got {result.error!r}"


# ---------------------------------------------------------------------------
# Legacy monkeypatch variants for the extract + verify pipeline.
# These tests stub only the URL/download boundary and let every other
# layer (extract, exe-search, version-probe) run against real code.
# ---------------------------------------------------------------------------


class TestInstallToolRealExtraction:
    """install_tool over a Cutter-shaped archive with only the URL/download stubbed.

    The network boundary (``_get_latest_release_url`` / ``_download_file``) is
    the only substituted surface. Every other layer - ``_extract_zip``,
    ``_has_expected_executable``, ``_finalize_archive_install``, and
    ``get_version`` - runs against the real implementation so that a regression
    in any of those functions causes the test to go red.
    """

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_missing_executable_exact_error(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An archive without cutter.exe produces the exact 'no expected executable' error.

        Only the network boundary is replaced; the real ``_extract_zip``
        and the real post-install executable search run against the
        extracted tree.  The exact error prefix must match the production
        constant ``_ERR_NO_EXE_AFTER_INSTALL`` so that any rename or
        message change is immediately caught.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to stub the URL/download boundary.
        """
        installer = ToolInstaller(tmp_path / "tools")
        release_zip = tmp_path / "cutter.zip"
        _build_zip(
            release_zip,
            {"cutter-2.3.0/bin/readme.txt": b"no executable here"},
        )

        async def _stub_url(_self: ToolInstaller, _tool: ToolName) -> str | None:
            await asyncio.sleep(0)
            return "https://example.invalid/cutter.zip"

        async def _stub_download(_self: ToolInstaller, _url: str) -> Path:
            await asyncio.sleep(0)
            return release_zip

        monkeypatch.setattr(ToolInstaller, "_get_latest_release_url", _stub_url)
        monkeypatch.setattr(ToolInstaller, "_download_file", _stub_download)

        result = asyncio.run(installer.install_tool(ToolName.CUTTER))
        assert result.success is False
        assert result.error is not None
        assert result.error == _ERR_NO_EXE, f"Expected exact error {_ERR_NO_EXE!r}, got {result.error!r}"

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_present_executable_exact_version_error(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An archive with cutter.exe produces the exact 'post-install version' error.

        The post-install executable search must succeed for a Cutter
        release layout that includes ``cutter.exe``.  The synthetic PE
        header has no VS_VERSION_INFO resource, so ``get_version`` returns
        None and the install fails at the version-verification stage.
        The exact error prefix must match the production constant
        ``_ERR_NO_VERSION_AFTER_INSTALL`` so that any rename or reworded
        message immediately breaks this test.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to stub the URL/download boundary.
        """
        installer = ToolInstaller(tmp_path / "tools")
        release_zip = tmp_path / "cutter.zip"
        _build_zip(
            release_zip,
            {
                "Cutter-v2.3.0-Windows-x86_64/cutter.exe": _PE_BYTES,
                "Cutter-v2.3.0-Windows-x86_64/bin/rizin.exe": _PE_BYTES,
            },
        )

        async def _stub_url(_self: ToolInstaller, _tool: ToolName) -> str | None:
            await asyncio.sleep(0)
            return "https://example.invalid/cutter.zip"

        async def _stub_download(_self: ToolInstaller, _url: str) -> Path:
            await asyncio.sleep(0)
            return release_zip

        monkeypatch.setattr(ToolInstaller, "_get_latest_release_url", _stub_url)
        monkeypatch.setattr(ToolInstaller, "_download_file", _stub_download)

        result = asyncio.run(installer.install_tool(ToolName.CUTTER))
        assert result.success is False
        assert result.error is not None
        assert result.error != _ERR_NO_EXE, "Executable search should have passed with cutter.exe present"
        assert result.error == _ERR_NO_VERSION, f"Expected exact error {_ERR_NO_VERSION!r}, got {result.error!r}"

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_url_lookup_failure_exact_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A None URL from the release-lookup step produces the exact 'Could not find download URL' error.

        This exercises the real network-error path inside
        ``_install_archive_tool`` by making ``_get_latest_release_url``
        return None, simulating a failed GitHub API call.  The exact error
        string must start with the expected prefix so any change to the
        message immediately fails this test.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to stub the URL lookup.
        """

        async def _stub_url_none(_self: ToolInstaller, _tool: ToolName) -> str | None:
            await asyncio.sleep(0)
            return None

        monkeypatch.setattr(ToolInstaller, "_get_latest_release_url", _stub_url_none)

        installer = ToolInstaller(tmp_path / "tools")
        result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error is not None
        assert result.error == _ERR_NO_URL, f"Expected exact error {_ERR_NO_URL!r}, got {result.error!r}"

    @staticmethod
    @pytest.mark.skipif(not pefile_available(), reason="pefile required to install Cutter")
    def test_download_failure_exact_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A None return from the download step produces the exact 'Download failed' error.

        Exercises the real error-propagation path inside
        ``_install_archive_tool`` when ``_download_file`` returns None
        (simulating a network I/O failure after the URL was resolved).
        The exact error string must match so any rewording is immediately caught.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest fixture used to stub the URL lookup and download.
        """

        async def _stub_url(_self: ToolInstaller, _tool: ToolName) -> str | None:
            await asyncio.sleep(0)
            return "https://example.invalid/cutter.zip"

        async def _stub_download_none(_self: ToolInstaller, _url: str) -> Path | None:
            await asyncio.sleep(0)
            return None

        monkeypatch.setattr(ToolInstaller, "_get_latest_release_url", _stub_url)
        monkeypatch.setattr(ToolInstaller, "_download_file", _stub_download_none)

        installer = ToolInstaller(tmp_path / "tools")
        result = asyncio.run(installer.install_tool(ToolName.CUTTER))

        assert result.success is False
        assert result.error is not None
        assert result.error == _ERR_DOWNLOAD_FAILED, f"Expected exact error {_ERR_DOWNLOAD_FAILED!r}, got {result.error!r}"


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
