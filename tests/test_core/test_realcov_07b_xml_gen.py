# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for :mod:`intellicrack.core.xml_gen`.

The audit flagged ``xml_gen.py`` as having only re-export identity coverage and
no integration with a real consumer. ``intellicrack.sandbox.windows`` is the
production consumer: ``WindowsSandbox._generate_wsb_config`` imports the
re-exported ``Element`` / ``SubElement`` / ``indent`` / ``ElementTree``
primitives directly from :mod:`intellicrack.core.xml_gen` and serialises a
Windows Sandbox ``.wsb`` configuration tree to disk.

These tests drive that real production generator end to end (no re-implemented
tree, no mocks), parse the emitted ``.wsb`` file back with a hardened
``defusedxml`` parser, and assert the exact node structure and values against
an independent oracle -- the :class:`SandboxConfig` dataclass inputs and the
documented Windows Sandbox schema constants -- so the test fails if the
re-exported primitives or the consumer's use of them ever regress.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import defusedxml.ElementTree as DefusedET
import pytest

from intellicrack.core.types import SandboxError
from intellicrack.core.xml_gen import (
    Element,
    ElementTree,
    SubElement,
    indent,
    tostring,
)
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path
    from xml.etree.ElementTree import Element as XmlElement


def _run_generate_wsb_config(sandbox: WindowsSandbox) -> None:
    """Run the production ``_generate_wsb_config`` coroutine to completion.

    Accesses the protected coroutine through :func:`getattr` so the test stays
    free of type-suppression directives while still exercising the real
    consumer of the :mod:`intellicrack.core.xml_gen` primitives.

    Args:
        sandbox: Sandbox whose protected ``_generate_wsb_config`` is invoked.
    """
    generate = getattr(sandbox, "_generate_wsb_config")
    asyncio.run(cast("Coroutine[Any, Any, None]", generate()))


def _generate_wsb(config: SandboxConfig, tmp_path: Path) -> bytes:
    """Drive the real production WSB generator and return the emitted bytes.

    Instantiates the production :class:`WindowsSandbox`, seeds the path state
    that ``initialize`` would normally set, and runs the real
    ``_generate_wsb_config`` coroutine which uses the re-exported
    :mod:`intellicrack.core.xml_gen` primitives.

    Args:
        config: Sandbox configuration that drives the generated XML values.
        tmp_path: Temporary directory used for the host shared folder and the
            output ``.wsb`` file.

    Returns:
        bytes: Raw serialised ``.wsb`` document as written to disk.
    """
    sandbox = WindowsSandbox(config)
    wsb_path = tmp_path / "config.wsb"
    setattr(sandbox, "_wsb_path", wsb_path)
    setattr(sandbox, "_shared_folder", tmp_path / "shared")
    _run_generate_wsb_config(sandbox)
    return wsb_path.read_bytes()


class TestWsbConfigGeneration:
    """The re-exported helpers must emit a real consumable WSB document.

    Every test runs the production ``WindowsSandbox._generate_wsb_config``
    consumer, which is the only first-party code path that exercises the
    write-side primitives re-exported by :mod:`intellicrack.core.xml_gen`.
    """

    def test_full_schema_matches_config_and_host_constants(self, tmp_path: Path) -> None:
        """Generated WSB mirrors the config dataclass and sandbox schema exactly.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        host_tool_dir = tmp_path / "host_tools"
        config = SandboxConfig(
            memory_limit_mb=4096,
            network_enabled=False,
            clipboard_enabled=True,
            audio_enabled=False,
            video_enabled=True,
            printer_enabled=False,
            shared_folders=[(host_tool_dir, r"C:\Tools", True)],
        )

        raw = _generate_wsb(config, tmp_path)
        assert raw.startswith(b"<?xml")

        root = DefusedET.fromstring(raw.decode("utf-8"))
        assert root.tag == "Configuration"

        # Scalar settings derive from the config booleans/ints (independent oracle).
        assert root.findtext("Networking") == "Disable"
        assert root.findtext("MemoryInMB") == "4096"
        assert root.findtext("vGPU") == "Enable"
        assert root.findtext("AudioInput") == "Disable"
        assert root.findtext("ClipboardRedirection") == "Enable"
        assert root.findtext("PrinterRedirection") == "Disable"

        # The first mapped folder is always the implicit Intellicrack shared dir,
        # mounted read-write at the documented guest path.
        folders = root.findall("MappedFolders/MappedFolder")
        assert len(folders) == 2

        implicit = folders[0]
        assert implicit.findtext("HostFolder") == str(tmp_path / "shared")
        assert implicit.findtext("SandboxFolder") == WindowsSandbox.SANDBOX_SHARED_PATH
        assert implicit.findtext("ReadOnly") == "false"

        # The second mapped folder is the user-supplied read-only mapping.
        user = folders[1]
        assert user.findtext("HostFolder") == str(host_tool_dir)
        assert user.findtext("SandboxFolder") == r"C:\Tools"
        assert user.findtext("ReadOnly") == "true"

        # The logon command launches the in-guest bootstrap at the guest path.
        expected_command = f'cmd.exe /c "{WindowsSandbox.SANDBOX_SHARED_PATH}\\monitor\\sandbox_bootstrap.cmd"'
        assert root.findtext("LogonCommand/Command") == expected_command

    def test_network_and_peripherals_enabled_toggle_values(self, tmp_path: Path) -> None:
        """Enabling every peripheral flips each scalar node to ``Enable``.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        config = SandboxConfig(
            memory_limit_mb=8192,
            network_enabled=True,
            clipboard_enabled=True,
            audio_enabled=True,
            video_enabled=True,
            printer_enabled=True,
        )

        raw = _generate_wsb(config, tmp_path)
        root = DefusedET.fromstring(raw.decode("utf-8"))

        assert root.findtext("Networking") == "Enable"
        assert root.findtext("MemoryInMB") == "8192"
        assert root.findtext("vGPU") == "Enable"
        assert root.findtext("AudioInput") == "Enable"
        assert root.findtext("ClipboardRedirection") == "Enable"
        assert root.findtext("PrinterRedirection") == "Enable"

        # With no user folders only the implicit shared mapping is present.
        assert len(root.findall("MappedFolders/MappedFolder")) == 1

    def test_zero_memory_limit_omits_memory_node(self, tmp_path: Path) -> None:
        """A non-positive memory limit must omit the ``MemoryInMB`` node entirely.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        config = SandboxConfig(memory_limit_mb=0)

        raw = _generate_wsb(config, tmp_path)
        root = DefusedET.fromstring(raw.decode("utf-8"))

        assert root.find("MemoryInMB") is None
        # The rest of the schema is still emitted so the host can consume it.
        assert root.findtext("Networking") == "Disable"
        assert root.findtext("vGPU") == "Disable"

    def test_indent_produces_human_readable_layout(self, tmp_path: Path) -> None:
        """The re-exported ``indent`` introduces newline/indentation between nodes.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        config = SandboxConfig(memory_limit_mb=2048)

        raw = _generate_wsb(config, tmp_path)
        text = raw.decode("utf-8")

        # Two-space indentation applied by the consumer must survive to disk.
        assert "\n  <MappedFolders>" in text
        assert "\n    <MappedFolder>" in text
        assert "\n      <HostFolder>" in text

        # Indentation must not corrupt round-tripping through a real parser.
        root = DefusedET.fromstring(text)
        assert root.findtext("vGPU") == "Disable"

    def test_special_characters_in_paths_are_escaped_and_recovered(self, tmp_path: Path) -> None:
        """Reserved XML characters in mapped-folder text are escaped, then recovered.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        guest_path = r'C:\Sand "<box>" & Co'
        config = SandboxConfig(
            shared_folders=[(tmp_path / "adv", guest_path, False)],
        )

        raw = _generate_wsb(config, tmp_path)
        text = raw.decode("utf-8")

        # The reserved characters must be entity-escaped in the serialised bytes,
        # never emitted raw inside element text.
        assert "&lt;box&gt;" in text
        assert "&amp; Co" in text
        assert "<box>" not in text.replace("&lt;box&gt;", "")

        # A hardened parser must recover the exact original unescaped string.
        root = DefusedET.fromstring(text)
        user = root.findall("MappedFolders/MappedFolder")[1]
        assert user.findtext("SandboxFolder") == guest_path

    def test_uninitialized_paths_raise_sandbox_error(self) -> None:
        """The consumer surfaces a ``SandboxError`` when paths are not initialized."""
        sandbox = WindowsSandbox(SandboxConfig())

        with pytest.raises(SandboxError, match="paths not initialized"):
            _run_generate_wsb_config(sandbox)

    def test_tostring_bytes_roundtrip_on_real_tree(self) -> None:
        """``tostring`` serialises an in-memory tree to byte-identical re-parseable XML.

        Builds a real ``MappedFolder`` subtree with the re-exported factories and
        confirms the default ``tostring`` byte output parses back to the same
        structure and values, covering the bytes branch the disk writer does not.
        """
        folder: XmlElement = Element("MappedFolder")
        SubElement(folder, "HostFolder").text = r"C:\host\samples"
        SubElement(folder, "SandboxFolder").text = WindowsSandbox.SANDBOX_SHARED_PATH
        SubElement(folder, "ReadOnly").text = "true"

        tree = ElementTree(folder)
        indent(tree, space="  ")

        raw = tostring(folder)
        assert isinstance(raw, bytes)

        root = DefusedET.fromstring(raw.decode("utf-8"))
        assert root.tag == "MappedFolder"
        assert root.findtext("HostFolder") == r"C:\host\samples"
        assert root.findtext("SandboxFolder") == WindowsSandbox.SANDBOX_SHARED_PATH
        assert root.findtext("ReadOnly") == "true"
