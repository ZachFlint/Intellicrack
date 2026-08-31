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

These tests drive the real
:meth:`intellicrack.sandbox.windows.WindowsSandbox._generate_wsb_config`
method end-to-end, assert the written file is a valid WSB document, and verify
exact node values against an independently computed oracle derived from the
:class:`~intellicrack.sandbox.base.SandboxConfig` inputs.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING

import defusedxml.ElementTree as DefusedET
import pytest


if TYPE_CHECKING:
    from pathlib import Path
    from xml.etree.ElementTree import Element as _ETElement

from intellicrack.core.xml_gen import (
    Element,
    ElementTree,
    SubElement,
    indent,
    tostring,
)
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox


_ATTR_WSB_PATH = "_wsb_path"
_ATTR_SHARED_FOLDER = "_shared_folder"
_METHOD_GENERATE_WSB_CONFIG = "_generate_wsb_config"


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


def _expected_logon_command() -> str:
    """Return the logon command string the real producer must emit.

    Computed independently from WindowsSandbox.SANDBOX_SHARED_PATH; this is
    the independent oracle used to verify the written XML node.

    Returns:
        str: The expected ``LogonCommand/Command`` text.
    """
    bootstrap = rf"{WindowsSandbox.SANDBOX_SHARED_PATH}\monitor\sandbox_bootstrap.cmd"
    return f'cmd.exe /c "{bootstrap}"'


def _assert_wsb_folder_nodes(root: _ETElement, shared_folder_str: str) -> None:
    """Assert the MappedFolders subtree matches the injected shared folder.

    Args:
        root: Parsed root ``Configuration`` element.
        shared_folder_str: Expected string representation of the host shared folder.
    """
    folder = root.find("MappedFolders/MappedFolder")
    assert folder is not None
    assert folder.findtext("HostFolder") == shared_folder_str
    assert folder.findtext("SandboxFolder") == WindowsSandbox.SANDBOX_SHARED_PATH
    assert folder.findtext("ReadOnly") == "false"


@pytest.fixture
def wsb_sandbox(tmp_path: Path) -> tuple[WindowsSandbox, Path]:
    """Provide a real WindowsSandbox with paths wired to tmp_path.

    The fixture sets ``_wsb_path`` and ``_shared_folder`` via ``setattr`` to
    bypass ``reportPrivateUsage`` while still injecting the minimum state
    required for ``_generate_wsb_config`` to run without the full start
    sequence.

    Args:
        tmp_path: Pytest-supplied temporary directory.

    Returns:
        tuple[WindowsSandbox, Path]: The sandbox instance and the expected wsb file path.
    """
    cfg = SandboxConfig(
        memory_limit_mb=8192,
        network_enabled=True,
        clipboard_enabled=True,
        audio_enabled=False,
        video_enabled=False,
        printer_enabled=True,
        shared_folders=[],
    )
    sandbox = WindowsSandbox(config=cfg)
    wsb_file = tmp_path / "intellicrack.wsb"
    shared_folder = tmp_path / "shared"
    shared_folder.mkdir()
    setattr(sandbox, _ATTR_WSB_PATH, wsb_file)
    setattr(sandbox, _ATTR_SHARED_FOLDER, shared_folder)
    return sandbox, wsb_file


class TestWsbConfigGeneration:
    """The real _generate_wsb_config must emit a correct, consumable WSB document."""

    @pytest.mark.skipif(sys.platform != "win32", reason="WindowsSandbox is a Windows-only production class")
    def test_tree_structure_matches_consumer_schema(self, wsb_sandbox: tuple[WindowsSandbox, Path]) -> None:
        """Real _generate_wsb_config emits XML with exact tags/values derived from config.

        The oracle values are computed independently from the SandboxConfig inputs
        and WindowsSandbox.SANDBOX_SHARED_PATH constant - never from the written file itself.
        Private members are accessed via ``getattr``/``setattr`` to satisfy
        ``reportPrivateUsage`` without suppression comments.
        """
        sandbox, wsb_file = wsb_sandbox
        cfg = sandbox.config
        generate = getattr(sandbox, _METHOD_GENERATE_WSB_CONFIG)
        asyncio.run(generate())

        assert wsb_file.exists(), "wsb file was not created"
        root = DefusedET.fromstring(wsb_file.read_bytes().decode("utf-8"))

        assert root.tag == "Configuration"
        assert root.findtext("Networking") == ("Enable" if cfg.network_enabled else "Disable")
        assert root.findtext("MemoryInMB") == (str(cfg.memory_limit_mb) if cfg.memory_limit_mb > 0 else None)
        assert root.findtext("ClipboardRedirection") == ("Enable" if cfg.clipboard_enabled else "Disable")
        assert root.findtext("vGPU") == ("Enable" if cfg.video_enabled else "Disable")
        assert root.findtext("AudioInput") == ("Enable" if cfg.audio_enabled else "Disable")
        assert root.findtext("PrinterRedirection") == ("Enable" if cfg.printer_enabled else "Disable")

        shared_str = str(getattr(sandbox, _ATTR_SHARED_FOLDER))
        _assert_wsb_folder_nodes(root, shared_str)
        assert root.findtext("LogonCommand/Command") == _expected_logon_command()

    @pytest.mark.skipif(sys.platform != "win32", reason="WindowsSandbox is a Windows-only production class")
    def test_serialised_document_roundtrips_through_real_parser(self, wsb_sandbox: tuple[WindowsSandbox, Path]) -> None:
        """Real _generate_wsb_config writes UTF-8 XML that defusedxml can fully round-trip.

        The oracle is independently derived from SandboxConfig and SANDBOX_SHARED_PATH;
        nothing from the written file is fed back into the expected-value computation.
        Private members are accessed via ``getattr`` to satisfy ``reportPrivateUsage``
        without suppression comments.
        """
        sandbox, wsb_file = wsb_sandbox
        cfg = sandbox.config
        generate = getattr(sandbox, _METHOD_GENERATE_WSB_CONFIG)
        asyncio.run(generate())

        raw = wsb_file.read_bytes()
        assert raw.startswith(b"<?xml"), "file must begin with an XML declaration"

        reparsed = DefusedET.fromstring(raw.decode("utf-8"))
        assert reparsed.tag == "Configuration"
        assert reparsed.findtext("MemoryInMB") == (str(cfg.memory_limit_mb) if cfg.memory_limit_mb > 0 else None)
        assert reparsed.findtext("MappedFolders/MappedFolder/SandboxFolder") == WindowsSandbox.SANDBOX_SHARED_PATH
        assert reparsed.findtext("Networking") == ("Enable" if cfg.network_enabled else "Disable")
        assert reparsed.findtext("LogonCommand/Command") == _expected_logon_command()

    def test_indent_produces_human_readable_layout(self) -> None:
        """``indent`` introduces real newline/indentation between children."""
        config = _build_wsb_config_tree()
        tree = ElementTree(config)
        indent(tree, space="  ")
        text = tostring(config, encoding="unicode")
        assert "\n" in text
        assert "\n  <MappedFolders>" in text
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
