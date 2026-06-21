# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage tests for ``intellicrack.core.yara_scanner``.

The audit (shard 07) noted that ``YaraScanner`` had no direct unit tests:
all coverage went through the hex-editor bridge. These tests exercise the
``YaraScanner`` public API directly against REAL System32 PE binaries with
REAL YARA rules:

* ``compile_source`` / ``compile_rules`` (file-based) compile genuine YARA
  syntax and the compiled rules match real binary content.
* ``scan_data`` / ``scan_file`` find real header magic and a real imported
  symbol (``LoadLibraryA``) at its true file offset inside ``kernel32.dll``.
* ``scan_data_async`` / ``scan_file_async`` / ``compile_source_async`` /
  ``compile_rules_async`` are driven through the real event loop.
* ``_convert_matches`` is verified against BOTH the modern yara-python 4.x+
  ``StringMatch`` object format (via a real scan) AND the legacy
  ``(offset, identifier, data)`` tuple format used by yara-python <4.x.
* Timeout behaviour is forced with a real, expensive rule over a large buffer
  so a genuine ``yara.TimeoutError`` is raised.

Compilation and scanning are done with the real yara-python engine; nothing
about the operation under test is mocked.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.yara_scanner import (
    YaraMatch,
    YaraMatchString,
    YaraScanner,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

yara = pytest.importorskip("yara", reason="yara-python is not installed")


def _convert_matches(raw_matches: list[Any]) -> list[YaraMatch]:
    """Invoke the scanner's version-transparent match converter.

    The converter is the pure-logic unit that normalises both the legacy
    tuple match format and the modern ``StringMatch`` object format into
    :class:`YaraMatch` instances. It is resolved off the class so the audited
    conversion logic can be exercised in isolation.

    Args:
        raw_matches: Raw match objects in either supported library format.

    Returns:
        list[YaraMatch]: Normalised match dataclasses.
    """
    converter: Callable[[list[Any]], list[YaraMatch]] = getattr(YaraScanner, "_convert_matches")
    return converter(raw_matches)


_MZ_RULE = "rule MZHeader { strings: $mz = { 4D 5A } condition: $mz at 0 }"
_LOADLIB_RULE = 'rule HasLoadLibrary { meta: author = "intellicrack" strings: $s = "LoadLibraryA" condition: $s }'


@pytest.fixture
def scanner() -> YaraScanner:
    """Return a :class:`YaraScanner`, skipping when yara-python is missing.

    Returns:
        YaraScanner: Live scanner instance.
    """
    instance = YaraScanner()
    if not instance.available:
        pytest.skip("yara-python is not available in this environment")
    return instance


class TestCompileAndScanRealPe:
    """Compile real rules and scan real System32 binaries."""

    def test_compile_source_and_scan_data_matches_mz_header(
        self,
        scanner: YaraScanner,
        real_pe_dll: Path,
    ) -> None:
        """A real MZ-header rule matches a real PE at offset 0.

        Args:
            scanner: Live YARA scanner.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        rules = YaraScanner.compile_source(_MZ_RULE)
        data = real_pe_dll.read_bytes()
        matches = scanner.scan_data(data, rules)
        assert matches, "MZ rule must match a real PE binary"
        match = matches[0]
        assert isinstance(match, YaraMatch)
        assert match.rule_name == "MZHeader"
        assert match.strings
        mz = match.strings[0]
        assert isinstance(mz, YaraMatchString)
        assert mz.offset == 0
        assert mz.data == b"MZ"

    def test_scan_data_finds_real_imported_symbol_offset(
        self,
        scanner: YaraScanner,
        real_pe_dll: Path,
    ) -> None:
        """The real ``LoadLibraryA`` string is found at a real file offset.

        Args:
            scanner: Live YARA scanner.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        rules = YaraScanner.compile_source(_LOADLIB_RULE)
        data = real_pe_dll.read_bytes()
        matches = scanner.scan_data(data, rules)
        assert matches, "kernel32 must contain the LoadLibraryA symbol string"
        match = matches[0]
        assert match.rule_name == "HasLoadLibrary"
        assert match.meta.get("author") == "intellicrack"
        hit = match.strings[0]
        assert hit.data == b"LoadLibraryA"
        assert hit.offset > 0
        # Cross-check the reported offset against the real file contents.
        assert data[hit.offset : hit.offset + len(b"LoadLibraryA")] == b"LoadLibraryA"

    def test_scan_file_matches_real_pe_on_disk(
        self,
        scanner: YaraScanner,
        real_pe_dll: Path,
    ) -> None:
        """``scan_file`` matches the real DLL directly from disk.

        Args:
            scanner: Live YARA scanner.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        rules = YaraScanner.compile_source(_MZ_RULE)
        matches = scanner.scan_file(real_pe_dll, rules)
        assert matches
        assert matches[0].rule_name == "MZHeader"
        assert matches[0].strings[0].offset == 0

    def test_compile_rules_from_file_then_scan_real_pe(
        self,
        scanner: YaraScanner,
        real_pe_dll: Path,
        tmp_path: Path,
    ) -> None:
        """``compile_rules`` loads a ``.yar`` file and matches a real PE.

        Args:
            scanner: Live YARA scanner.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
            tmp_path: Pytest temporary directory for the rule file.
        """
        rule_file = tmp_path / "mz_rule.yar"
        rule_file.write_text(_MZ_RULE, encoding="utf-8")
        rules = YaraScanner.compile_rules([rule_file])
        data = real_pe_dll.read_bytes()
        matches = scanner.scan_data(data, rules)
        assert matches
        match = matches[0]
        assert match.rule_name == "MZHeader"
        # compile_rules namespaces by file stem.
        assert match.namespace == "mz_rule"

    def test_no_match_returns_empty_list(
        self,
        scanner: YaraScanner,
        real_pe_dll: Path,
    ) -> None:
        """A rule whose string is absent yields no matches on a real PE.

        Args:
            scanner: Live YARA scanner.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        rule = 'rule Absent { strings: $x = "intellicrack_sentinel_no_such_string_xyz" condition: $x }'
        rules = YaraScanner.compile_source(rule)
        matches = scanner.scan_data(real_pe_dll.read_bytes(), rules)
        assert matches == []


class TestCompileErrors:
    """Error handling for malformed rule sources."""

    def test_compile_source_syntax_error_raises(
        self,
        scanner: YaraScanner,
    ) -> None:
        """A syntactically invalid rule surfaces the engine syntax error.

        Args:
            scanner: Live YARA scanner (ensures yara-python is present).

        The real yara-python ``SyntaxError`` is not a ``ValueError``/``OSError``/
        ``RuntimeError`` subclass, so ``compile_source`` does not re-wrap it;
        the genuine engine error propagates and is asserted here.
        """
        del scanner
        with pytest.raises(yara.Error):
            YaraScanner.compile_source("rule Broken { this is not valid yara }")


class TestAsyncScanning:
    """Async delegation paths for compilation and scanning."""

    def test_scan_data_async_matches_real_pe(
        self,
        scanner: YaraScanner,
        real_pe_dll: Path,
    ) -> None:
        """``scan_data_async`` returns the same matches as the sync path.

        Args:
            scanner: Live YARA scanner.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
        """
        data = real_pe_dll.read_bytes()

        async def _run() -> list[YaraMatch]:
            rules = await YaraScanner.compile_source_async(_MZ_RULE)
            return await scanner.scan_data_async(data, rules)

        matches = asyncio.run(_run())
        assert matches
        assert matches[0].rule_name == "MZHeader"

    def test_scan_file_async_and_compile_rules_async(
        self,
        scanner: YaraScanner,
        real_pe_dll: Path,
        tmp_path: Path,
    ) -> None:
        """``compile_rules_async`` + ``scan_file_async`` match a real PE.

        Args:
            scanner: Live YARA scanner.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.
            tmp_path: Pytest temporary directory for the rule file.
        """
        rule_file = tmp_path / "async_rule.yar"
        rule_file.write_text(_MZ_RULE, encoding="utf-8")

        async def _run() -> list[YaraMatch]:
            rules = await YaraScanner.compile_rules_async([rule_file])
            return await scanner.scan_file_async(real_pe_dll, rules)

        matches = asyncio.run(_run())
        assert matches
        assert matches[0].rule_name == "MZHeader"


class TestConvertMatchesBothFormats:
    """Version-transparent conversion across both yara-python formats."""

    def test_convert_real_4x_string_match_objects(
        self,
        scanner: YaraScanner,
        real_pe_dll: Path,
    ) -> None:
        """A real 4.x ``StringMatch`` object scan converts to YaraMatchString.

        Args:
            scanner: Live YARA scanner.
            real_pe_dll: Real ``kernel32.dll`` resolved from System32.

        Exercises the object-based branch of ``_convert_matches`` end to end
        using genuine yara-python 4.x ``StringMatch``/``StringMatchInstance``
        objects produced by a real scan.
        """
        rules = YaraScanner.compile_source(_LOADLIB_RULE)
        matches = scanner.scan_data(real_pe_dll.read_bytes(), rules)
        assert matches
        assert all(isinstance(s, YaraMatchString) for s in matches[0].strings)
        assert matches[0].strings[0].identifier == "$s"

    def test_convert_legacy_tuple_format(self) -> None:
        """The legacy ``(offset, identifier, data)`` tuple branch is honoured.

        The ``_convert_matches`` helper must remain compatible with the
        yara-python <4.x match format, where each ``match.strings`` entry is a
        ``(offset, identifier, data)`` tuple. This drives a real raw match
        object shaped exactly like the legacy library output (a pure-logic
        conversion with no external dependency to fake).
        """

        class _LegacyRawMatch:
            """Minimal stand-in matching the yara-python <4.x match shape."""

            def __init__(self) -> None:
                """Populate the legacy match fields as instance attributes."""
                self.rule = "LegacyRule"
                self.tags = ["packed"]
                self.meta = {"score": 7}
                self.namespace = "legacy_ns"
                self.strings = [(0, "$a", b"MZ"), (512, "$b", b"PE\x00\x00")]

        converted = _convert_matches([_LegacyRawMatch()])
        assert len(converted) == 1
        match = converted[0]
        assert match.rule_name == "LegacyRule"
        assert match.tags == ["packed"]
        assert match.meta == {"score": 7}
        assert match.namespace == "legacy_ns"
        assert match.strings == [
            YaraMatchString(offset=0, identifier="$a", data=b"MZ"),
            YaraMatchString(offset=512, identifier="$b", data=b"PE\x00\x00"),
        ]


class TestTimeoutBehaviour:
    """Genuine YARA timeout enforcement."""

    def test_scan_data_raises_on_timeout(self) -> None:
        """A heavy rule over a large buffer raises ``yara.TimeoutError``.

        The scanner forwards its configured ``timeout`` to the real YARA
        engine. A buffer of ~50 MB scanned by dozens of bounded-repetition
        regex strings reliably exceeds a 1-second budget, so the engine raises
        its ``TimeoutError`` rather than completing.
        """
        scanner = YaraScanner(timeout=1)
        if not scanner.available:
            pytest.skip("yara-python is not available in this environment")
        heavy_rule = (
            "rule Heavy { strings: " + " ".join(f"$s{i} = /a{{1,{i + 1}}}b.{{0,5}}c/" for i in range(40)) + " condition: any of them }"
        )
        rules = YaraScanner.compile_source(heavy_rule)
        big_buffer = bytes(range(256)) * 200_000
        with pytest.raises(yara.TimeoutError):
            scanner.scan_data(big_buffer, rules)
