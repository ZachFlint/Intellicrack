# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for audit F1 -- SectionInfo carries a raw file offset.

Cross-tool navigation maps a section's virtual address to a raw file offset so
the hex editor can scroll there. That requires ``SectionInfo`` to record the raw
file offset (PE ``PointerToRawData`` / ELF ``sh_offset``). This test parses a
real PE (the running Python interpreter) and asserts the orchestrator's section
extractor copies each section's file offset into ``SectionInfo.raw_offset``.

Falsified by reverting the ``raw_offset=...`` population (every section would
default to 0, and the ``.text`` file offset is non-zero in a real PE).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import lief

from intellicrack.core import orchestrator as orchestrator_mod


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.types import SectionInfo

    _LiefParseFn = Callable[[str], object]
    _ExtractSectionsFn = Callable[[object], list[SectionInfo]]


def test_section_raw_offset_matches_pe_file_offset() -> None:
    """``_extract_sections`` must copy each PE section's file offset verbatim.

    Parses the real ``python.exe`` PE and asserts that every extracted
    ``SectionInfo.raw_offset`` equals the corresponding LIEF section file
    offset, and that the executable ``.text`` section has a non-zero offset
    (which the pre-fix default of 0 could never satisfy).
    """
    pe_path = Path(sys.executable)
    parse_fn = cast("_LiefParseFn", vars(lief)["parse"])
    parsed = parse_fn(str(pe_path))
    assert isinstance(parsed, lief.PE.Binary), "python.exe did not parse as a PE binary"

    extract_sections = cast("_ExtractSectionsFn", vars(orchestrator_mod)["_extract_sections"])
    sections = extract_sections(parsed)
    assert sections, "no sections extracted from the real PE"

    lief_offset_by_name = {str(sec.name): int(sec.offset) for sec in parsed.sections}
    for section in sections:
        assert section.name in lief_offset_by_name, f"unexpected section name {section.name!r}"
        assert section.raw_offset == lief_offset_by_name[section.name], f"raw_offset for {section.name!r} does not match the PE file offset"

    text_section = next((s for s in sections if s.name.startswith(".text")), None)
    assert text_section is not None, "real PE unexpectedly has no .text section"
    assert text_section.raw_offset > 0, "raw_offset was left at the default 0 (F1 regression)"
