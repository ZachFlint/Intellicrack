# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for :mod:`intellicrack.core.xml_gen`.

The audit flagged ``xml_gen.py`` as having only re-export identity coverage and
no integration with a real consumer. ``intellicrack.sandbox.windows`` is the
production consumer: it builds a Windows Sandbox ``.wsb`` configuration tree
from the re-exported ``Element`` / ``SubElement`` / ``indent`` / ``ElementTree``
/ ``tostring`` primitives and serialises it to disk.

These tests reproduce the exact node structure that
``WindowsSandbox._generate_wsb_config`` emits, serialise it with the
re-exported helpers, and parse it back with a hardened parser to prove the
generated XML is real, well-formed, and schema-faithful to what the Windows
Sandbox host actually consumes.
"""

from __future__ import annotations

import io

import defusedxml.ElementTree as DefusedET

from intellicrack.core.xml_gen import (
    Element,
    ElementTree,
    SubElement,
    indent,
    tostring,
)


def _build_wsb_config_tree() -> Element:
    """Build a Windows Sandbox configuration tree like the real consumer.

    Mirrors the node structure produced by
    :meth:`intellicrack.sandbox.windows.WindowsSandbox._generate_wsb_config`
    using the re-exported XML generation primitives.

    Returns:
        Element: The root ``Configuration`` element.
    """
    config = Element("Configuration")

    mapped_folders = SubElement(config, "MappedFolders")
    folder = SubElement(mapped_folders, "MappedFolder")
    SubElement(folder, "HostFolder").text = "C:/Intellicrack/shared"
    SubElement(folder, "SandboxFolder").text = r"C:\shared"
    SubElement(folder, "ReadOnly").text = "false"

    SubElement(config, "Networking").text = "Disable"
    SubElement(config, "MemoryInMB").text = "4096"
    SubElement(config, "vGPU").text = "Disable"
    SubElement(config, "AudioInput").text = "Disable"
    SubElement(config, "ClipboardRedirection").text = "Enable"
    SubElement(config, "PrinterRedirection").text = "Disable"

    logon_command = SubElement(config, "LogonCommand")
    SubElement(logon_command, "Command").text = r'cmd.exe /c "C:\shared\monitor\sandbox_bootstrap.cmd"'

    return config


class TestWsbConfigGeneration:
    """The re-exported helpers must emit a real consumable WSB document."""

    def test_tree_structure_matches_consumer_schema(self) -> None:
        """Built nodes carry the exact tags/text the sandbox host expects."""
        config = _build_wsb_config_tree()
        assert config.tag == "Configuration"
        assert config.find("Networking") is not None
        assert config.findtext("Networking") == "Disable"
        assert config.findtext("MemoryInMB") == "4096"
        assert config.findtext("ClipboardRedirection") == "Enable"

        folder = config.find("MappedFolders/MappedFolder")
        assert folder is not None
        assert folder.findtext("HostFolder") == "C:/Intellicrack/shared"
        assert folder.findtext("SandboxFolder") == r"C:\shared"
        assert folder.findtext("ReadOnly") == "false"

        command = config.findtext("LogonCommand/Command")
        assert command is not None
        assert command.startswith("cmd.exe /c")

    def test_serialised_document_roundtrips_through_real_parser(self) -> None:
        """Serialised XML parses back to the same logical structure."""
        config = _build_wsb_config_tree()
        tree = ElementTree(config)
        indent(tree, space="  ")

        buffer = io.BytesIO()
        tree.write(buffer, encoding="utf-8", xml_declaration=True)
        raw = buffer.getvalue()

        assert raw.startswith(b"<?xml")
        reparsed = DefusedET.fromstring(raw.decode("utf-8"))
        assert reparsed.tag == "Configuration"
        assert reparsed.findtext("MemoryInMB") == "4096"
        assert reparsed.findtext("MappedFolders/MappedFolder/SandboxFolder") == r"C:\shared"

    def test_indent_produces_human_readable_layout(self) -> None:
        """``indent`` introduces real newline/indentation between children."""
        config = _build_wsb_config_tree()
        tree = ElementTree(config)
        indent(tree, space="  ")
        text = tostring(config, encoding="unicode")
        assert "\n" in text
        assert "\n  <MappedFolders>" in text
        # Indentation must not corrupt round-tripping.
        reparsed = DefusedET.fromstring(text)
        assert reparsed.findtext("vGPU") == "Disable"

    def test_special_characters_in_text_are_escaped(self) -> None:
        """Reserved XML characters in node text are escaped and recoverable."""
        config = Element("Configuration")
        command = SubElement(config, "Command")
        command.text = 'run --flag "a<b>&c"'
        serialized = tostring(config, encoding="unicode")
        assert "&lt;" in serialized
        assert "&amp;" in serialized
        reparsed = DefusedET.fromstring(serialized)
        assert reparsed.findtext("Command") == 'run --flag "a<b>&c"'

    def test_tostring_bytes_default_encoding(self) -> None:
        """``tostring`` returns bytes whose content parses to the same tree."""
        config = _build_wsb_config_tree()
        raw = tostring(config)
        assert isinstance(raw, bytes)
        reparsed = DefusedET.fromstring(raw.decode("utf-8"))
        assert reparsed.tag == "Configuration"
        assert len(reparsed.findall("MappedFolders/MappedFolder")) == 1
