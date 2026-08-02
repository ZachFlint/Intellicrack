# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D12 (backend half): one ``.wsb`` generator, one element spelling.

Intellicrack shipped two independent ``.wsb`` XML generators that disagreed.
The backend built its document with ``ElementTree`` and emitted ``<vGPU>``; the
configuration dialog's sandbox test concatenated strings and emitted ``<VGpu>``.
Windows Sandbox accepts only one spelling, so at most one of them could ever be
right, and the backend is the one verified to boot a real guest.

Both call sites now build through :mod:`intellicrack.sandbox.wsb`. These gates
pin the shared generator's element spelling and its escaping of
caller-supplied text, plus the backend call site that consumes it. The dialog
half lives in ``tests/ui/test_wsb_generator_convergence_s17d12.py``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import defusedxml.ElementTree as DefusedET

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox
from intellicrack.sandbox.wsb import (
    WSB_VGPU_ELEMENT,
    WsbMappedFolder,
    build_wsb_configuration,
    render_wsb_configuration,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


_ACCEPTED_VGPU_SPELLING = "vGPU"
_WRONG_VGPU_SPELLING = "VGpu"
_ATTR_WSB_PATH = "_wsb_path"
_ATTR_SHARED_FOLDER = "_shared_folder"
_METHOD_GENERATE_WSB_CONFIG = "_generate_wsb_config"
_HOSTILE_DIR_NAME = "loot & <archive>"
_DEFAULT_LOGON = "cmd.exe /c exit"


def _render(
    *,
    logon_command: str = _DEFAULT_LOGON,
    mapped_folders: Sequence[WsbMappedFolder] = (),
    networking_enabled: bool = False,
    memory_limit_mb: int = 0,
    video_enabled: bool = False,
    audio_enabled: bool | None = None,
    clipboard_enabled: bool | None = None,
    printer_enabled: bool | None = None,
) -> str:
    """Build and serialize a configuration, returning the decoded document.

    Args:
        logon_command: Guest logon command line.
        mapped_folders: Folder mappings to expose to the guest.
        networking_enabled: Whether the guest gets a network adapter.
        memory_limit_mb: Guest memory budget in megabytes.
        video_enabled: Whether the guest gets a virtualized GPU.
        audio_enabled: Audio redirection toggle, or None to omit it.
        clipboard_enabled: Clipboard redirection toggle, or None to omit it.
        printer_enabled: Printer redirection toggle, or None to omit it.

    Returns:
        str: The rendered ``.wsb`` document text.
    """
    configuration = build_wsb_configuration(
        logon_command=logon_command,
        mapped_folders=mapped_folders,
        networking_enabled=networking_enabled,
        memory_limit_mb=memory_limit_mb,
        video_enabled=video_enabled,
        audio_enabled=audio_enabled,
        clipboard_enabled=clipboard_enabled,
        printer_enabled=printer_enabled,
    )
    return render_wsb_configuration(configuration).decode("utf-8")


def _wired_sandbox(tmp_path: Path, *, video_enabled: bool) -> tuple[WindowsSandbox, Path]:
    """Build a real ``WindowsSandbox`` with only its path state injected.

    Args:
        tmp_path: Pytest temporary directory fixture.
        video_enabled: Value for ``SandboxConfig.video_enabled``.

    Returns:
        tuple[WindowsSandbox, Path]: The sandbox and the ``.wsb`` path it writes.
    """
    config = SandboxConfig(
        memory_limit_mb=4096,
        network_enabled=True,
        clipboard_enabled=True,
        audio_enabled=False,
        video_enabled=video_enabled,
        printer_enabled=False,
        shared_folders=[],
    )
    sandbox = WindowsSandbox(config=config)
    wsb_file = tmp_path / "intellicrack.wsb"
    shared_folder = tmp_path / "shared"
    shared_folder.mkdir()
    setattr(sandbox, _ATTR_WSB_PATH, wsb_file)
    setattr(sandbox, _ATTR_SHARED_FOLDER, shared_folder)
    return sandbox, wsb_file


def _generate(sandbox: WindowsSandbox) -> None:
    """Run the backend's protected ``.wsb`` generator to completion.

    Args:
        sandbox: Sandbox whose path state has been wired by :func:`_wired_sandbox`.
    """
    generate = getattr(sandbox, _METHOD_GENERATE_WSB_CONFIG)
    asyncio.run(generate())


class TestSharedGeneratorSpelling:
    """The shared generator must emit the spelling Windows Sandbox accepts."""

    def test_vgpu_element_uses_the_accepted_casing(self) -> None:
        """The GPU toggle is ``vGPU``; the rejected ``VGpu`` never appears.

        ``VGpu`` is what the dialog's hand-rolled generator used to emit, and a
        sandbox configured with it does not get the toggle applied.
        """
        document = _render(video_enabled=True)
        assert f"<{_ACCEPTED_VGPU_SPELLING}>Enable</{_ACCEPTED_VGPU_SPELLING}>" in document, (
            f"expected the accepted vGPU spelling in:\n{document}"
        )
        assert _WRONG_VGPU_SPELLING not in document, f"the rejected spelling must not survive:\n{document}"

    def test_vgpu_constant_is_the_documented_spelling(self) -> None:
        """The exported element-name constant is literally ``vGPU``."""
        assert WSB_VGPU_ELEMENT == _ACCEPTED_VGPU_SPELLING

    def test_gpu_toggle_tracks_the_requested_state(self) -> None:
        """``video_enabled`` drives Enable/Disable rather than a fixed value."""
        enabled = DefusedET.fromstring(_render(video_enabled=True))
        disabled = DefusedET.fromstring(_render(video_enabled=False))
        assert enabled.findtext(_ACCEPTED_VGPU_SPELLING) == "Enable"
        assert disabled.findtext(_ACCEPTED_VGPU_SPELLING) == "Disable"

    def test_optional_toggles_are_omitted_when_unspecified(self) -> None:
        """Toggles left at ``None`` produce no element at all."""
        root = DefusedET.fromstring(_render(video_enabled=True))
        assert root.find("AudioInput") is None
        assert root.find("ClipboardRedirection") is None
        assert root.find("PrinterRedirection") is None
        assert root.find("MemoryInMB") is None
        assert root.find("MappedFolders") is None

    def test_optional_toggles_are_emitted_when_specified(self) -> None:
        """Explicit toggle flags reach the document with matching values."""
        root = DefusedET.fromstring(
            _render(
                video_enabled=False,
                audio_enabled=True,
                clipboard_enabled=False,
                printer_enabled=True,
                memory_limit_mb=4096,
                networking_enabled=True,
            ),
        )
        assert root.findtext("AudioInput") == "Enable"
        assert root.findtext("ClipboardRedirection") == "Disable"
        assert root.findtext("PrinterRedirection") == "Enable"
        assert root.findtext("MemoryInMB") == "4096"
        assert root.findtext("Networking") == "Enable"


class TestSharedGeneratorEscaping:
    """Caller-supplied text must be escaped, not interpolated."""

    def test_host_path_with_xml_metacharacters_roundtrips(self) -> None:
        """A host path containing ``&`` and ``<`` survives a real parse.

        String concatenation of this value yields a document that no XML parser
        will accept, which is what the dialog's generator produced.
        """
        host = Path("D:/samples") / _HOSTILE_DIR_NAME
        document = _render(
            mapped_folders=[WsbMappedFolder(host_folder=host, sandbox_folder=r"C:\Shared", read_only=False)],
        )
        assert "&amp;" in document, f"the ampersand must be escaped in:\n{document}"
        root = DefusedET.fromstring(document)
        assert root.findtext("MappedFolders/MappedFolder/HostFolder") == str(host)

    def test_logon_command_with_metacharacters_roundtrips(self) -> None:
        """A ``&&`` command chain survives serialization and parsing."""
        command = 'cmd.exe /c "echo a && echo <b>"'
        root = DefusedET.fromstring(_render(logon_command=command))
        assert root.findtext("LogonCommand/Command") == command


class TestBackendCallSite:
    """``WindowsSandbox`` must produce the shared document on disk."""

    def test_written_config_uses_the_accepted_vgpu_spelling(self, tmp_path: Path) -> None:
        """The file the backend writes carries ``vGPU`` and never ``VGpu``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sandbox, wsb_file = _wired_sandbox(tmp_path, video_enabled=True)
        _generate(sandbox)

        document = wsb_file.read_bytes().decode("utf-8")
        assert f"<{_ACCEPTED_VGPU_SPELLING}>Enable</{_ACCEPTED_VGPU_SPELLING}>" in document
        assert _WRONG_VGPU_SPELLING not in document

    def test_extra_shared_folder_with_metacharacters_roundtrips(self, tmp_path: Path) -> None:
        """A configured shared folder containing ``&``/``<`` stays parseable.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sandbox, wsb_file = _wired_sandbox(tmp_path, video_enabled=False)
        hostile = tmp_path / _HOSTILE_DIR_NAME
        sandbox.config.shared_folders.append((hostile, r"C:\Extra", True))

        _generate(sandbox)

        root = DefusedET.fromstring(wsb_file.read_bytes().decode("utf-8"))
        folders = root.findall("MappedFolders/MappedFolder")
        hosts = [folder.findtext("HostFolder") for folder in folders]
        assert str(hostile) in hosts, f"the configured folder must reach the document; saw {hosts!r}"
        extra = folders[-1]
        assert extra.findtext("SandboxFolder") == r"C:\Extra"
        assert extra.findtext("ReadOnly") == "true"

    def test_primary_shared_folder_and_logon_command_are_preserved(self, tmp_path: Path) -> None:
        """Converging on the shared builder keeps the dispatcher wiring intact.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sandbox, wsb_file = _wired_sandbox(tmp_path, video_enabled=False)
        _generate(sandbox)

        raw = wsb_file.read_bytes()
        assert raw.startswith(b"<?xml"), "the written file must carry an XML declaration"
        root = DefusedET.fromstring(raw.decode("utf-8"))
        assert root.findtext("MappedFolders/MappedFolder/SandboxFolder") == WindowsSandbox.SANDBOX_SHARED_PATH
        assert root.findtext("MappedFolders/MappedFolder/HostFolder") == str(getattr(sandbox, _ATTR_SHARED_FOLDER))
        command = root.findtext("LogonCommand/Command")
        assert command is not None
        assert command.endswith('sandbox_bootstrap.cmd"'), f"the dispatcher bootstrap must still be launched; got {command!r}"
