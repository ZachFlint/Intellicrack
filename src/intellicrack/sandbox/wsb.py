# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Windows Sandbox ``.wsb`` configuration document construction.

Single source of truth for the XML consumed by ``WindowsSandbox.exe``. Both the
sandbox backend (:mod:`intellicrack.sandbox.windows`) and the sandbox
configuration dialog's connectivity test build their documents through this
module so the two can never disagree about element spelling, element ordering,
or the escaping of caller-supplied text such as host folder paths.

Element spelling matters: Windows Sandbox accepts ``vGPU`` and rejects other
casings, and a host path containing ``&`` or ``<`` produces an unparseable
document unless it is escaped, so every value is written through
:mod:`xml.etree.ElementTree` rather than interpolated into a string.

The module deliberately imports neither Qt nor anything from
:mod:`intellicrack.ui`, so the UI layer can consume it without an import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING, Final

from intellicrack.core.xml_gen import Element, ElementTree, SubElement, indent


if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path


WSB_VGPU_ELEMENT: Final[str] = "vGPU"

_ENABLE: Final[str] = "Enable"
_DISABLE: Final[str] = "Disable"
_INDENT_SPACE: Final[str] = "  "
_OPTIONAL_TOGGLE_ELEMENTS: Final[tuple[str, str, str]] = (
    "AudioInput",
    "ClipboardRedirection",
    "PrinterRedirection",
)


def _toggle(*, enabled: bool) -> str:
    """Map a feature flag onto its ``.wsb`` toggle keyword.

    Args:
        enabled: Whether the feature should be active inside the guest.

    Returns:
        str: ``"Enable"`` when ``enabled`` is true, otherwise ``"Disable"``.
    """
    return _ENABLE if enabled else _DISABLE


@dataclass(frozen=True, slots=True)
class WsbMappedFolder:
    """One host-to-guest folder mapping of a ``.wsb`` document.

    Attributes:
        host_folder: Host directory exposed to the guest.
        sandbox_folder: Absolute guest path the directory is mounted at.
        read_only: Whether the guest is denied write access to the mapping.
    """

    host_folder: Path
    sandbox_folder: str
    read_only: bool


def build_wsb_configuration(
    *,
    logon_command: str,
    mapped_folders: Iterable[WsbMappedFolder] = (),
    networking_enabled: bool = False,
    memory_limit_mb: int = 0,
    video_enabled: bool = False,
    audio_enabled: bool | None = None,
    clipboard_enabled: bool | None = None,
    printer_enabled: bool | None = None,
) -> Element:
    """Build the ``Configuration`` element of a Windows Sandbox document.

    Args:
        logon_command: Command line run inside the guest once it has booted.
        mapped_folders: Folder mappings to expose to the guest. ``MappedFolders``
            is omitted entirely when no mapping is supplied.
        networking_enabled: Whether the guest gets a network adapter.
        memory_limit_mb: Guest memory budget in megabytes. Values of zero or
            below omit ``MemoryInMB`` so Windows applies its own default.
        video_enabled: Whether the guest gets a virtualized GPU.
        audio_enabled: Whether guest audio input is redirected, or ``None`` to
            omit ``AudioInput`` and inherit the host default.
        clipboard_enabled: Whether clipboard redirection is enabled, or ``None``
            to omit ``ClipboardRedirection``.
        printer_enabled: Whether printer redirection is enabled, or ``None`` to
            omit ``PrinterRedirection``.

    Returns:
        Element: Root ``Configuration`` element ready for serialization by
        :func:`render_wsb_configuration`.
    """
    configuration = Element("Configuration")

    folders = list(mapped_folders)
    if folders:
        mapped = SubElement(configuration, "MappedFolders")
        for entry in folders:
            folder = SubElement(mapped, "MappedFolder")
            SubElement(folder, "HostFolder").text = str(entry.host_folder)
            SubElement(folder, "SandboxFolder").text = entry.sandbox_folder
            SubElement(folder, "ReadOnly").text = "true" if entry.read_only else "false"

    SubElement(configuration, "Networking").text = _toggle(enabled=networking_enabled)

    if memory_limit_mb > 0:
        SubElement(configuration, "MemoryInMB").text = str(memory_limit_mb)

    SubElement(configuration, WSB_VGPU_ELEMENT).text = _toggle(enabled=video_enabled)

    optional_flags: tuple[bool | None, bool | None, bool | None] = (audio_enabled, clipboard_enabled, printer_enabled)
    for name, flag in zip(_OPTIONAL_TOGGLE_ELEMENTS, optional_flags, strict=True):
        if flag is not None:
            SubElement(configuration, name).text = _toggle(enabled=flag)

    logon = SubElement(configuration, "LogonCommand")
    SubElement(logon, "Command").text = logon_command

    return configuration


def render_wsb_configuration(configuration: Element) -> bytes:
    """Serialize a ``Configuration`` element into ``.wsb`` file bytes.

    Args:
        configuration: Root element produced by :func:`build_wsb_configuration`.

    Returns:
        bytes: Indented UTF-8 XML document prefixed with an XML declaration.
    """
    tree = ElementTree(configuration)
    indent(tree, space=_INDENT_SPACE)
    buffer = BytesIO()
    tree.write(buffer, encoding="utf-8", xml_declaration=True)
    return buffer.getvalue()


__all__: list[str] = [
    "WSB_VGPU_ELEMENT",
    "WsbMappedFolder",
    "build_wsb_configuration",
    "render_wsb_configuration",
]
