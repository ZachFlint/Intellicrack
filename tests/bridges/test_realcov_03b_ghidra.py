# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage tests for GhidraBridge pure-logic capabilities.

The audit (shard 03) flagged that every existing GhidraBridge test is a
structural metadata check or a disconnected ``ToolError`` assertion: none
exercises a real capability against a real artifact. A live Ghidra headless
JVM plus its ``ghidra_bridge`` RPC server is not available in the test
container, so the RPC-dependent analysis methods are correctly gated behind
connection state. However, a substantial part of the bridge's real behaviour
is deterministic, dependency-free logic that operates on genuine inputs:

* binary-format and CPU-architecture detection driven by the magic bytes and
  machine fields of REAL PE / ELF / Mach-O binaries,
* the wildcarded hex-pattern parser that feeds Ghidra's ``findBytes`` masked
  search and sign-folds bytes into the JVM ``jarray('b')`` range,
* the Jython script preparer that rewrites a trailing expression into a
  uniquely named sentinel global via a real AST round-trip,
* the Ghidra ``RefType`` taxonomy mapper and the cross-reference builder it
  feeds,
* the debug-info path canonicaliser that defeats traversal against real
  filesystem paths,
* the headless-launch helpers (executable resolution, environment scrubbing).

Each test asserts on the real, verifiable result of the operation against a
real input, not that a call happened and not on a value the test injected.

Protected bridge methods are exercised through :class:`_GhidraProbe`, a thin
subclass that re-exposes them with public names (a subclass may legitimately
access its parent's protected members). Module-private helpers are fetched by
name from the bridge module so the real implementation is exercised directly.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
from typing import TYPE_CHECKING, Any, Final

import pytest

import intellicrack.bridges.ghidra as ghidra_module
from intellicrack.bridges.ghidra import GhidraBridge, prepare_remote_script
from intellicrack.core.types import CrossReference, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path


_HEADER_BYTES: Final[int] = 4096
_JAVA_SIGNED_MIN: Final[int] = -128
_JAVA_SIGNED_MAX: Final[int] = 127

_map_ghidra_ref_type: Callable[[str], str] = getattr(ghidra_module, "_map_ghidra_ref_type")
_resolve_debug_info_path: Callable[[str], Path] = getattr(ghidra_module, "_resolve_debug_info_path")
_headless_env_blocklist: Sequence[str] = getattr(ghidra_module, "_HEADLESS_ENV_BLOCKLIST")


class _GhidraProbe(GhidraBridge):
    """Test subclass that re-exposes protected helpers with public names.

    A subclass may access its parent's protected members, so this wrapper
    lets the real, type-checked implementation be driven directly without
    weakening any visibility contract on the production bridge.
    """

    def detect_format(self, data: bytes) -> str:
        """Detect the binary format of ``data``.

        Args:
            data: Leading bytes of a real binary.

        Returns:
            str: Detected format label.
        """
        return self._detect_format(data)

    def detect_architecture(self, data: bytes) -> tuple[str, bool]:
        """Detect the CPU architecture of ``data``.

        Args:
            data: Leading bytes of a real binary.

        Returns:
            tuple[str, bool]: Tuple of (architecture, is_64bit).
        """
        return self._detect_architecture(data)

    def parse_hex_search_pattern(self, raw_hex: str) -> tuple[list[int], list[int]]:
        """Parse a wildcarded hex pattern into signed byte/mask arrays.

        Args:
            raw_hex: Hex search pattern, optionally with ``??`` wildcards.

        Returns:
            tuple[list[int], list[int]]: Sign-folded ``(byte_vals, mask_vals)``.
        """
        return self._parse_hex_search_pattern(raw_hex)

    def build_cross_reference(self, payload: dict[str, Any]) -> CrossReference:
        """Build a CrossReference from a Ghidra xref payload.

        Args:
            payload: Xref payload dict as produced by the remote script.

        Returns:
            CrossReference: Populated cross-reference instance.
        """
        return self._build_cross_reference(payload)

    def scrubbed_environment(self) -> dict[str, str]:
        """Return the scrubbed launch environment.

        Returns:
            dict[str, str]: Environment with hijack-prone variables removed.
        """
        return self._scrubbed_environment()

    def resolve_headless_executable(self, ghidra_path: Path) -> Path:
        """Resolve the platform ``analyzeHeadless`` launcher.

        Args:
            ghidra_path: Root directory of a Ghidra installation.

        Returns:
            Path: Path to the resolved launcher.
        """
        return self._resolve_headless_executable(ghidra_path)


@pytest.fixture
def probe() -> _GhidraProbe:
    """Create a fresh probing GhidraBridge instance.

    Returns:
        _GhidraProbe: A disconnected bridge whose pure-logic helpers are
        exercised against real inputs.
    """
    return _GhidraProbe()


def _read_header(path: Path) -> bytes:
    """Read the leading header bytes of a real binary fixture.

    Args:
        path: Path to a real binary on disk.

    Returns:
        bytes: The first :data:`_HEADER_BYTES` bytes of the file, which is
        sufficient for magic-byte and machine-field detection.
    """
    return path.read_bytes()[:_HEADER_BYTES]


class TestRealFormatDetection:
    """Detect the format of real PE, ELF, and Mach-O binaries from their bytes."""

    def test_real_pe_dll_detected_as_pe(self, probe: _GhidraProbe, real_pe_dll: Path) -> None:
        """Detect a real System32 DLL as a PE binary.

        Args:
            probe: GhidraBridge probe fixture.
            real_pe_dll: Path to a real PE DLL (kernel32.dll).
        """
        assert probe.detect_format(_read_header(real_pe_dll)) == "pe"

    def test_real_pe_exe_detected_as_pe(self, probe: _GhidraProbe, real_pe_exe: Path) -> None:
        """Detect a real System32 executable as a PE binary.

        Args:
            probe: GhidraBridge probe fixture.
            real_pe_exe: Path to a real PE executable (notepad.exe).
        """
        assert probe.detect_format(_read_header(real_pe_exe)) == "pe"

    def test_real_elf_detected_as_elf(self, probe: _GhidraProbe, real_elf_binary: Path) -> None:
        """Detect the committed real ELF fixture as an ELF binary.

        Args:
            probe: GhidraBridge probe fixture.
            real_elf_binary: Path to the committed real ELF binary.
        """
        assert probe.detect_format(_read_header(real_elf_binary)) == "elf"

    def test_real_macho_detected_as_macho(self, probe: _GhidraProbe, real_macho_binary: Path) -> None:
        """Detect the committed real Mach-O fixture as a Mach-O binary.

        Args:
            probe: GhidraBridge probe fixture.
            real_macho_binary: Path to the committed real Mach-O binary.
        """
        assert probe.detect_format(_read_header(real_macho_binary)) == "macho"

    def test_formats_are_distinct(
        self,
        probe: _GhidraProbe,
        real_pe_dll: Path,
        real_elf_binary: Path,
        real_macho_binary: Path,
    ) -> None:
        """Verify the detector distinguishes the three real binary families.

        Args:
            probe: GhidraBridge probe fixture.
            real_pe_dll: Path to a real PE DLL.
            real_elf_binary: Path to the committed real ELF binary.
            real_macho_binary: Path to the committed real Mach-O binary.
        """
        detected = {
            probe.detect_format(_read_header(real_pe_dll)),
            probe.detect_format(_read_header(real_elf_binary)),
            probe.detect_format(_read_header(real_macho_binary)),
        }
        assert detected == {"pe", "elf", "macho"}


class TestRealArchitectureDetection:
    """Detect the CPU architecture of real 64-bit binaries from their headers."""

    def test_real_pe_dll_arch(self, probe: _GhidraProbe, real_pe_dll: Path) -> None:
        """Detect kernel32.dll as 64-bit x86_64 from its PE machine field.

        Args:
            probe: GhidraBridge probe fixture.
            real_pe_dll: Path to a real 64-bit PE DLL.
        """
        arch, is_64 = probe.detect_architecture(_read_header(real_pe_dll))
        assert arch == "x86_64"
        assert is_64 is True

    def test_real_elf_arch(self, probe: _GhidraProbe, real_elf_binary: Path) -> None:
        """Detect the real ELF fixture as 64-bit x86_64 from its e_machine field.

        Args:
            probe: GhidraBridge probe fixture.
            real_elf_binary: Path to the committed real x86_64 ELF binary.
        """
        arch, is_64 = probe.detect_architecture(_read_header(real_elf_binary))
        assert arch == "x86_64"
        assert is_64 is True

    def test_real_macho_arch(self, probe: _GhidraProbe, real_macho_binary: Path) -> None:
        """Detect the real Mach-O fixture as 64-bit x86_64 from its cputype field.

        Args:
            probe: GhidraBridge probe fixture.
            real_macho_binary: Path to the committed real x86_64 Mach-O binary.
        """
        arch, is_64 = probe.detect_architecture(_read_header(real_macho_binary))
        assert arch == "x86_64"
        assert is_64 is True


class TestRealHexPatternParsing:
    """Parse real wildcarded hex search patterns into JVM-signed arrays."""

    def test_spaced_pattern_with_wildcards(self, probe: _GhidraProbe) -> None:
        """Parse a space-delimited pattern with a wildcard byte.

        The ``48 8B`` prefix is the canonical x86-64 ``mov r64, r/m64``
        opcode prelude; the parser must produce ``0xFF`` masks for fixed
        bytes and a ``(0x00, 0x00)`` pair for the ``??`` wildcard, all
        sign-folded into the ``-128..127`` range Ghidra's ``jarray('b')``
        accepts.

        Args:
            probe: GhidraBridge probe fixture.
        """
        byte_vals, mask_vals = probe.parse_hex_search_pattern("48 8B ?? FF")
        assert byte_vals == [0x48, 0x8B - 256, 0x00, 0xFF - 256]
        assert mask_vals == [0xFF - 256, 0xFF - 256, 0x00, 0xFF - 256]

    def test_contiguous_pattern_split_into_byte_pairs(self, probe: _GhidraProbe) -> None:
        """Parse a whitespace-free pattern by splitting into two-digit tokens.

        Args:
            probe: GhidraBridge probe fixture.
        """
        byte_vals, mask_vals = probe.parse_hex_search_pattern("4889E5")
        assert byte_vals == [0x48, 0x89 - 256, 0xE5 - 256]
        assert mask_vals == [0xFF - 256, 0xFF - 256, 0xFF - 256]

    def test_all_bytes_fold_into_signed_range(self, probe: _GhidraProbe) -> None:
        """Verify every parsed byte and mask is a valid signed Java byte.

        Args:
            probe: GhidraBridge probe fixture.
        """
        byte_vals, mask_vals = probe.parse_hex_search_pattern("00 7F 80 FF ??")
        for value in (*byte_vals, *mask_vals):
            assert _JAVA_SIGNED_MIN <= value <= _JAVA_SIGNED_MAX

    def test_wildcard_token_question_single(self, probe: _GhidraProbe) -> None:
        """Verify a single ``?`` token is treated as a full-byte wildcard.

        Args:
            probe: GhidraBridge probe fixture.
        """
        byte_vals, mask_vals = probe.parse_hex_search_pattern("90 ? 90")
        assert byte_vals == [0x90 - 256, 0x00, 0x90 - 256]
        assert mask_vals == [0xFF - 256, 0x00, 0xFF - 256]

    def test_empty_pattern_rejected(self, probe: _GhidraProbe) -> None:
        """Verify an empty pattern raises ToolError rather than emitting bytes.

        Args:
            probe: GhidraBridge probe fixture.
        """
        with pytest.raises(ToolError, match="empty"):
            probe.parse_hex_search_pattern("   ")

    def test_malformed_token_rejected(self, probe: _GhidraProbe) -> None:
        """Verify a non-hex token raises ToolError.

        Args:
            probe: GhidraBridge probe fixture.
        """
        with pytest.raises(ToolError, match="Malformed hex token"):
            probe.parse_hex_search_pattern("48 ZZ")


class TestRealJythonScriptPreparation:
    """Round-trip real Jython source through the trailing-expression rewriter."""

    def test_trailing_expression_rewritten_to_sentinel(self) -> None:
        """Verify a trailing expression is captured into a sentinel global."""
        source, sentinel = prepare_remote_script("x = 1\nx + 2")
        assert sentinel is not None
        assert sentinel in source
        assert f"{sentinel} = x + 2" in source

    def test_rewritten_source_is_valid_python_and_preserves_value(self) -> None:
        """Verify the rewritten script parses and the sentinel holds the value."""
        source, sentinel = prepare_remote_script("a = 6\nb = 7\na * b")
        assert sentinel is not None
        ast.parse(source, mode="exec")
        namespace: dict[str, object] = {}
        exec(compile(source, "<remote>", "exec"), namespace)
        assert namespace[sentinel] == 42

    def test_no_trailing_expression_leaves_no_sentinel(self) -> None:
        """Verify an assignment-only script yields no sentinel and parses."""
        source, sentinel = prepare_remote_script("value = 5")
        assert sentinel is None
        ast.parse(source, mode="exec")

    def test_empty_script_returns_empty(self) -> None:
        """Verify whitespace-only source yields an empty rewrite and no sentinel."""
        source, sentinel = prepare_remote_script("   \n   ")
        assert not source
        assert sentinel is None

    def test_invalid_syntax_raises_tool_error(self) -> None:
        """Verify unparseable Jython source raises ToolError."""
        with pytest.raises(ToolError, match="Failed to parse remote script"):
            prepare_remote_script("def broken(:\n    pass")

    def test_json_dumps_payload_survives_round_trip(self) -> None:
        """Verify an injection-laden string embedded via json.dumps stays inert.

        This proves the bridge's real defence: a hostile label/comment value
        is serialised with ``json.dumps`` and embedded as a Jython string
        literal. After the script preparer's AST round-trip the malicious
        payload must remain a single string constant, never executable code.
        """
        malicious = 'evil"; import os; os.system("calc"); "'
        embedded = json.dumps(malicious)
        source, sentinel = prepare_remote_script(f"label = {embedded}\nlabel")
        assert sentinel is not None
        namespace: dict[str, object] = {}
        exec(compile(source, "<remote>", "exec"), namespace)
        assert namespace[sentinel] == malicious
        assert namespace["label"] == malicious


class TestRealRefTypeMapping:
    """Map real Ghidra RefType strings to the canonical xref taxonomy."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("UNCONDITIONAL_CALL", "call"),
            ("COMPUTED_CALL", "call"),
            ("CONDITIONAL_JUMP", "jump"),
            ("COMPUTED_JUMP", "jump"),
            ("UNCONDITIONAL_JUMP", "jump"),
            ("FLOW", "jump"),
            ("FALL_THROUGH_FLOW", "jump"),
            ("READ", "read"),
            ("READ_IND", "read"),
            ("WRITE", "write"),
            ("WRITE_IND", "write"),
            ("READ_WRITE", "write"),
            ("DATA", "data"),
            ("PARAM", "data"),
            ("EXTERNAL_REF", "data"),
        ],
    )
    def test_ref_type_taxonomy(self, raw: str, expected: str) -> None:
        """Verify each real Ghidra RefType maps to the right canonical kind.

        Args:
            raw: A RefType string as emitted by Ghidra's RefType.toString().
            expected: The canonical xref kind the bridge must produce.
        """
        assert _map_ghidra_ref_type(raw) == expected

    def test_cross_reference_built_from_call_payload(self, probe: _GhidraProbe) -> None:
        """Verify a Ghidra call-xref payload yields a typed CrossReference.

        Args:
            probe: GhidraBridge probe fixture.
        """
        payload: dict[str, Any] = {
            "from": 0x401000,
            "to": 0x402000,
            "type": "UNCONDITIONAL_CALL",
            "from_function": "main",
            "to_function": "helper",
        }
        xref = probe.build_cross_reference(payload)
        assert isinstance(xref, CrossReference)
        assert xref.from_address == 0x401000
        assert xref.to_address == 0x402000
        assert xref.ref_type == "call"
        assert xref.from_function == "main"
        assert xref.to_function == "helper"

    def test_cross_reference_write_payload_preserves_write_kind(self, probe: _GhidraProbe) -> None:
        """Verify a data-write xref payload is not collapsed to plain data.

        Args:
            probe: GhidraBridge probe fixture.
        """
        xref = probe.build_cross_reference({"from": 0x10, "to": 0x20, "type": "WRITE"})
        assert xref.ref_type == "write"
        assert xref.from_function is None
        assert xref.to_function is None


class TestRealDebugInfoPathResolution:
    """Canonicalise real filesystem paths for the debug-info importer."""

    def test_resolves_real_file_to_absolute(self, real_pe_dll: Path) -> None:
        """Verify an existing real file resolves to an absolute path.

        Args:
            real_pe_dll: Path to a real file on disk (kernel32.dll).
        """
        resolved = _resolve_debug_info_path(str(real_pe_dll))
        assert resolved.is_absolute()
        assert resolved.is_file()
        assert resolved.samefile(real_pe_dll)

    def test_nonexistent_path_rejected(self, tmp_path: Path) -> None:
        """Verify a non-existent path raises ToolError.

        Args:
            tmp_path: Pytest temporary directory.
        """
        missing = tmp_path / "no_such_debug_info.pdb"
        with pytest.raises(ToolError, match="not found"):
            _resolve_debug_info_path(str(missing))

    def test_directory_rejected(self, tmp_path: Path) -> None:
        """Verify a directory path is rejected as not a regular file.

        Args:
            tmp_path: Pytest temporary directory.
        """
        with pytest.raises(ToolError, match="not a regular file"):
            _resolve_debug_info_path(str(tmp_path))

    def test_empty_path_rejected(self) -> None:
        """Verify a blank path raises ToolError before touching the filesystem."""
        with pytest.raises(ToolError, match="invalid"):
            _resolve_debug_info_path("   ")

    def test_traversal_sequence_resolved_against_real_root(self, real_pe_dll: Path) -> None:
        """Verify a traversal sequence canonicalises onto the real target file.

        Constructs ``<System32>/drivers/../kernel32.dll`` from a real DLL and
        confirms the resolver collapses the ``..`` segment to the genuine
        file rather than leaving the dot-dot in place.

        Args:
            real_pe_dll: Path to a real PE DLL inside System32.
        """
        traversal = real_pe_dll.parent / "drivers" / ".." / real_pe_dll.name
        resolved = _resolve_debug_info_path(str(traversal))
        assert resolved.samefile(real_pe_dll)
        assert ".." not in resolved.parts


class TestRealHeadlessLaunchHelpers:
    """Exercise headless-launch helpers without spawning a JVM."""

    def test_scrubbed_environment_strips_jvm_hijack_variables(self, probe: _GhidraProbe) -> None:
        """Verify hijack-prone variables are removed from the launch environment.

        Args:
            probe: GhidraBridge probe fixture.
        """
        env = probe.scrubbed_environment()
        for key in _headless_env_blocklist:
            assert key not in env

    def test_resolve_headless_executable_missing_install_raises(
        self,
        probe: _GhidraProbe,
        tmp_path: Path,
    ) -> None:
        """Verify a directory lacking analyzeHeadless raises ToolError.

        Args:
            probe: GhidraBridge probe fixture.
            tmp_path: Pytest temporary directory standing in for a bogus
                Ghidra install root.
        """
        with pytest.raises(ToolError, match="headless script not found"):
            probe.resolve_headless_executable(tmp_path)

    def test_resolve_headless_executable_finds_real_launcher(
        self,
        probe: _GhidraProbe,
        tmp_path: Path,
    ) -> None:
        """Verify the platform launcher under support/ is located when present.

        Builds a real on-disk Ghidra-shaped layout (a ``support`` directory
        holding the platform launcher) and confirms the resolver returns the
        genuine file path.

        Args:
            probe: GhidraBridge probe fixture.
            tmp_path: Pytest temporary directory used as a fake install root.
        """
        support = tmp_path / "support"
        support.mkdir()
        launcher = support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        launcher.write_text("@echo off\n", encoding="utf-8")
        resolved = probe.resolve_headless_executable(tmp_path)
        assert resolved.samefile(launcher)


class TestRealAvailability:
    """Exercise availability reporting against real installation state."""

    @pytest.mark.asyncio
    async def test_is_available_false_without_path(self, probe: _GhidraProbe) -> None:
        """Verify is_available is False when no Ghidra path is configured.

        Args:
            probe: GhidraBridge probe fixture.
        """
        assert await probe.is_available() is False

    @pytest.mark.asyncio
    async def test_is_available_reflects_path_and_package(
        self,
        probe: _GhidraProbe,
        tmp_path: Path,
    ) -> None:
        """Verify availability depends on both a set path and the RPC package.

        With a real path configured, availability is driven solely by whether
        the ``ghidra_bridge`` package is importable in this interpreter; the
        test asserts the result agrees with the genuine import-spec lookup.

        Args:
            probe: GhidraBridge probe fixture.
            tmp_path: Pytest temporary directory used as the install path.
        """
        probe.ghidra_path = tmp_path
        expected = importlib.util.find_spec("ghidra_bridge") is not None
        assert await probe.is_available() is expected
