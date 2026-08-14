# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Generator for the hexbench design-system preview cards.

Running this module writes one self-contained HTML file per component specimen
into ``design/cards``. Every card inlines ``static/app.css`` so it renders under
a strict content security policy without a single external request, and carries
a ``@dsCard`` marker on its first line so a gallery can group the files without
parsing them.

The cards are static, and their sample data is computed at build time rather
than invented: the editor cards render a real 640 byte 64-bit PE image header,
and the analysis cards measure a 16 KiB continuation of that same image whose
code, string, padding and packed regions exercise the full entropy and
classification range.
"""

from __future__ import annotations

import math
import struct
import sys
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from itertools import pairwise, starmap
from pathlib import Path
from typing import Final


__all__ = ["build_cards", "main", "sample_bytes"]

type _Json = str | int | float | bool | dict[str, _Json] | list[_Json] | None

_HERE: Final = Path(__file__).resolve().parent
_CARDS_DIR: Final = _HERE / "cards"
_CSS_PATH: Final = _HERE.parent / "static" / "app.css"

_ROW_WIDTH: Final = 16
_GROUP_SIZE: Final = 8
_NULL_BYTE: Final = 0x00
_PRINT_LOW: Final = 0x20
_PRINT_HIGH: Final = 0x7E
_HIGH_LOW: Final = 0x80
_ENTROPY_WINDOW: Final = 256
_CLASS_BLOCK: Final = 256
_HIGH_ENTROPY: Final = 7.0
_MID_ENTROPY: Final = 4.5
_MAX_ENTROPY: Final = 8.0
_TEXT_SHARE: Final = 0.9
_DIGRAM_SIDE: Final = 256
_HISTOGRAM_BINS: Final = 256
_STRIP_HEIGHT: Final = 64.0
_STRIP_STEP: Final = 4.0
_PERCENT: Final = 100.0
_PAYLOAD_ROWS: Final = 8
_MARKER_START: Final = 0x2800
_MARKER_LENGTH: Final = 0x0C00
_MIN_OPACITY: Final = 0.25
_OPACITY_RANGE: Final = 0.75

_PAD_AFTER_HEADER: Final = 384
_CODE_LENGTH: Final = 8192
_TEXT_LENGTH: Final = 3072
_GAP_LENGTH: Final = 1024
_PACKED_LENGTH: Final = 3072
_PACKED_SEED: Final = 0x5A4D90031F2E4B6C
_LCG_MULTIPLIER: Final = 6364136223846793005
_LCG_INCREMENT: Final = 1442695040888963407
_LCG_MASK: Final = (1 << 64) - 1
_LCG_DISCARD: Final = 24
_LCG_CHUNK: Final = 5

_CODE_PATTERNS: Final[tuple[str, ...]] = (
    "4889e5",
    "4883ec20",
    "488b05",
    "e8",
    "4885c0",
    "7412",
    "488d0d",
    "ff15",
    "8b4424",
    "89442404",
    "4c8d05",
    "ba",
    "b901000000",
    "4883c420",
    "c3",
    "0f1f440000",
    "4c8bdc",
    "49895b08",
    "4157",
    "4881ec90000000",
    "33db",
    "8bf1",
    "488bfa",
    "3bc3",
    "0f8ca4000000",
)

_TEXT_FRAGMENTS: Final[tuple[str, ...]] = (
    "KERNEL32.dll",
    "GetProcAddress",
    "LoadLibraryExW",
    "VirtualProtect",
    "RtlCaptureContext",
    "UnhandledExceptionFilter",
    "api-ms-win-core-synch-l1-2-0.dll",
    "Unknown exception",
    "bad allocation",
    "invalid string position",
    "C:\\build\\release\\intellicrack.pdb",
    "Microsoft Visual C++ Runtime Library",
    "operator new",
    "std::_Xlength_error",
)

_SAMPLE_ROWS: Final[tuple[str, ...]] = (
    "4d5a90000300000004000000ffff0000",
    "b8000000000000004000000000000000",
    "00000000000000000000000000000000",
    "000000000000000000000000f0000000",
    "0e1fba0e00b409cd21b8014ccd215468",
    "69732070726f6772616d2063616e6e6f",
    "742062652072756e20696e20444f5320",
    "6d6f64652e0d0d0a2400000000000000",
    "c3a43b7f87c5552c87c5552c87c5552c",
    "8ebdc62c82c5552c8ebdc42c8ac5552c",
    "8ebdc12c8cc5552c87c5542cc0c5552c",
    "4fa2c12c86c5552c4fa2c02c86c5552c",
    "4fa2c52c86c5552c5269636887c5552c",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "50450000648606006b1c5f6500000000",
    "00000000f00022000b020e2a006a0100",
    "005c010000000000603f010000100000",
    "00000040010000000010000000020000",
    "06000000000000000600000000000000",
    "00400300000600000000000003006081",
    "00002000000000000010000000000000",
    "00001000000000000010000000000000",
    "00000000100000000000000000000000",
    "5c2e02008c0000000000000000000000",
    "00300300900500000000000000000000",
    "0000000000000000602002001c000000",
    "00000000000000000000000000000000",
    "0000000000000000f01f020040010000",
    "00000000000000000020020040000000",
    "00000000000000000000000000000000",
    "00000000000000002e74657874000000",
    "c869010000100000006a010000060000",
    "00000000000000000000000020000060",
    "2e726461746100003aa1000000800100",
    "00a20000007001000000000000000000",
    "00000000400000402e64617461000000",
    "381e000000300200000a000000120200",
    "000000000000000000000000400000c0",
    "2e706461746100009005000000300300",
)

_SAMPLE_REGIONS: Final[tuple[tuple[int, int, str], ...]] = (
    (0x03C, 0x03F, "is-bookmarked"),
    (0x040, 0x04D, "is-selected"),
    (0x0F0, 0x0F3, "is-field"),
    (0x0F4, 0x0F5, "is-field"),
    (0x0F6, 0x0F7, "is-field"),
    (0x100, 0x107, "is-diff-modified"),
    (0x148, 0x14B, "is-diff-added"),
    (0x14C, 0x14D, "is-modified"),
    (0x1F8, 0x1FC, "is-hit"),
    (0x220, 0x225, "is-hit"),
    (0x248, 0x24C, "is-hit"),
)

_SAMPLE_CARET: Final = 0x04A
_SAMPLE_CURRENT_ROW: Final = 0x040

_DIFF_BANDS: Final[tuple[tuple[float, float, str, str], ...]] = (
    (0.0, 14.0, "is-match", "="),
    (14.0, 6.0, "is-modified", "~"),
    (20.0, 21.0, "is-match", "="),
    (41.0, 4.0, "is-inserted-b", "+"),
    (45.0, 13.0, "is-match", "="),
    (58.0, 7.0, "is-inserted-a", "-"),
    (65.0, 9.0, "is-match", "="),
    (74.0, 5.0, "is-modified", "~"),
    (79.0, 21.0, "is-match", "="),
)

_DIFF_LEGEND: Final[tuple[tuple[str, str, str], ...]] = (
    ("=", "--hb-class-0", "match"),
    ("~", "--hb-diff-modified-bg", "modified"),
    ("-", "--hb-diff-removed-bg", "inserted_a"),
    ("+", "--hb-diff-added-bg", "inserted_b"),
)

_CLASS_LEGEND: Final[tuple[tuple[int, str, str], ...]] = (
    (0, "Zero filled", "every byte 0x00"),
    (1, "Plaintext-like", "printable, low entropy"),
    (2, "Moderate", "structured binary"),
    (3, "High entropy", "H &gt; 7.0, packed or encrypted"),
    (4, "Mixed", "H 4.5 to 7.0, code or tables"),
)

_BYTE_CLASSES: Final[tuple[tuple[str, str, str, int], ...]] = (
    ("bc-null", "null", "0x00", 0x00),
    ("bc-print", "printable", "0x20 to 0x7E", 0x41),
    ("bc-ctrl", "control", "below 0x20, and 0x7F", 0x0D),
    ("bc-high", "high", "0x80 to 0xFF", 0xC3),
)

_BYTE_CLASS_VARS: Final[tuple[str, ...]] = ("null", "printable", "control", "high")

_COLOUR_TOKENS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    (
        "Surface",
        (
            "--hb-surface-0",
            "--hb-surface-1",
            "--hb-surface-2",
            "--hb-surface-3",
            "--hb-surface-inset",
            "--hb-surface-hover",
            "--hb-surface-active",
            "--hb-surface-code",
        ),
    ),
    ("Border", ("--hb-border-subtle", "--hb-border", "--hb-border-strong", "--hb-border-focus")),
    (
        "Text",
        (
            "--hb-text-primary",
            "--hb-text-secondary",
            "--hb-text-muted",
            "--hb-text-faint",
            "--hb-text-accent",
            "--hb-text-link",
            "--hb-text-inverse",
        ),
    ),
    ("Accent", ("--hb-accent", "--hb-accent-hover", "--hb-accent-active", "--hb-accent-subtle", "--hb-accent-muted", "--hb-on-accent")),
    ("Semantic", ("--hb-success", "--hb-warning", "--hb-error", "--hb-info", "--hb-neutral")),
    ("Semantic wash", ("--hb-success-bg", "--hb-warning-bg", "--hb-error-bg", "--hb-info-bg", "--hb-neutral-bg")),
    ("Byte class", ("--hb-byte-null", "--hb-byte-printable", "--hb-byte-control", "--hb-byte-high")),
    (
        "Editor state",
        (
            "--hb-sel-bg",
            "--hb-caret",
            "--hb-modified",
            "--hb-bookmark",
            "--hb-hit-bg",
            "--hb-field-bg",
            "--hb-diff-added-bg",
            "--hb-diff-removed-bg",
            "--hb-diff-modified-bg",
        ),
    ),
    ("Classification", ("--hb-class-0", "--hb-class-1", "--hb-class-2", "--hb-class-3", "--hb-class-4")),
    ("Chart", ("--hb-chart-grid", "--hb-chart-axis", "--hb-chart-fill", "--hb-chart-line", "--hb-chart-ink")),
)

_TYPE_SCALE: Final[tuple[tuple[str, str, str], ...]] = (
    ("--hb-fs-3xl", "28px", "document title"),
    ("--hb-fs-2xl", "22px", "dialog heading"),
    ("--hb-fs-xl", "18px", "palette query"),
    ("--hb-fs-lg", "15px", "section heading"),
    ("--hb-fs-md", "13px", "body and controls"),
    ("--hb-fs-sm", "12px", "dense tables, hex data"),
    ("--hb-fs-xs", "11px", "status bar, captions"),
    ("--hb-fs-2xs", "10px", "column labels, badges"),
)

_WEIGHTS: Final[tuple[str, ...]] = ("regular", "medium", "semibold", "bold")

_SPACE_SCALE: Final[tuple[tuple[str, int], ...]] = (
    ("--hb-space-1", 2),
    ("--hb-space-2", 4),
    ("--hb-space-3", 6),
    ("--hb-space-4", 8),
    ("--hb-space-5", 12),
    ("--hb-space-6", 16),
    ("--hb-space-7", 20),
    ("--hb-space-8", 24),
    ("--hb-space-9", 32),
    ("--hb-space-10", 40),
    ("--hb-space-11", 56),
    ("--hb-space-12", 72),
)

_RADII: Final[tuple[tuple[str, str], ...]] = (
    ("--hb-radius-xs", "2px"),
    ("--hb-radius-sm", "3px"),
    ("--hb-radius-md", "5px"),
    ("--hb-radius-lg", "8px"),
    ("--hb-radius-xl", "12px"),
    ("--hb-radius-pill", "999px"),
)

_ELEVATIONS: Final[tuple[tuple[str, str], ...]] = (
    ("--hb-shadow-0", "flush, in-flow surfaces"),
    ("--hb-shadow-1", "panel frames, cards at rest"),
    ("--hb-shadow-2", "hovered cards, result frames"),
    ("--hb-shadow-3", "menus, popovers, toasts"),
    ("--hb-shadow-4", "command palette, modal dialogs"),
)

_CELL_STATES: Final[tuple[tuple[str, str, str], ...]] = (
    ("", "normal", "no state"),
    ("is-selected", "selected", "inside the active selection"),
    ("is-selected-inactive", "selected, unfocused", "selection while another pane has focus"),
    ("is-caret", "caret", "caret cell, whole byte"),
    ("is-caret is-nibble-left", "nibble caret, high", "editing the high nibble"),
    ("is-caret is-nibble-right", "nibble caret, low", "editing the low nibble"),
    ("is-caret-inactive", "caret, unfocused", "caret position with focus elsewhere"),
    ("is-modified", "modified", "unsaved edit"),
    ("is-bookmarked", "bookmarked", "corner flag plus ring"),
    ("is-hit is-hit-start", "search hit, first byte", "leading edge bar"),
    ("is-hit", "search hit", "inside a match"),
    ("is-field is-field-start", "template field, start", "left cap of a field run"),
    ("is-field", "template field", "inside a field run"),
    ("is-field is-field-end", "template field, end", "right cap of a field run"),
    ("is-diff-added", "diff added", "present only in B"),
    ("is-diff-removed", "diff removed", "present only in A"),
    ("is-diff-modified", "diff modified", "differs between A and B"),
)

_CELL_COMBOS: Final[tuple[tuple[str, str], ...]] = (
    ("is-selected is-modified", "selected + modified"),
    ("is-selected is-hit", "selected + search hit"),
    ("is-selected is-modified is-hit", "selected + modified + hit"),
    ("is-caret is-selected is-modified", "caret + selected + modified"),
    ("is-caret is-nibble-right is-selected is-hit", "nibble caret + selected + hit"),
    ("is-bookmarked is-field is-field-start", "bookmarked + field start"),
    ("is-bookmarked is-selected is-modified", "bookmarked + selected + modified"),
    ("is-diff-modified is-hit is-selected", "diff + hit + selected"),
    ("is-caret is-bookmarked is-diff-added is-hit", "caret over three region states"),
)

_MENU_ENTRIES: Final[tuple[tuple[str, str, bool], ...]] = (
    ("Open File...", "Ctrl+O", True),
    ("Open Bytes...", "Ctrl+Shift+O", True),
    ("Attach To Process...", "Ctrl+Alt+P", True),
    ("", "", True),
    ("Save", "Ctrl+S", True),
    ("Save As...", "Ctrl+Shift+S", True),
    ("Revert", "", False),
    ("", "", True),
    ("Export Patches (IPS)...", "", True),
    ("Import Patches (BPS)...", "", True),
    ("", "", True),
    ("Close Document", "Ctrl+W", True),
)

_MENU_TITLES: Final[tuple[str, ...]] = ("Edit", "View", "Analyse", "Tools", "Help")

_DOCUMENT_TABS: Final[tuple[tuple[str, bool, bool], ...]] = (
    ("kernel32.dll", True, True),
    ("firmware.bin", False, False),
    ("license.dat", False, True),
    ("pid 8124 @ 0x7FF6C21A0000", False, False),
)

_DOCK_TABS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("Inspector", "", True),
    ("Bookmarks", "4", False),
    ("Template", "48", False),
    ("Strings", "212", False),
    ("Patches", "4", False),
)

_BOTTOM_DOCK_TABS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("Strings", "212", True),
    ("Search", "4", False),
    ("Entropy", "", False),
    ("Diff", "9", False),
    ("Log", "", False),
)

_SHELL_ROWS: Final = 24
_SHELL_HEIGHT: Final = 660

_ENGINE_STATES: Final[tuple[tuple[str, str, str], ...]] = (
    ("is-ready", "engine ready", "engine"),
    ("is-busy", "transform_data running", "engine"),
    ("is-error", "last call failed", "engine"),
)

_PALETTE_GROUPS: Final[tuple[tuple[str, tuple[tuple[str, str, str, str], ...]], ...]] = (
    (
        "Search",
        (
            ("search", "_bytes", "(pattern: bytes) -&gt; list[tuple[int, int]]", "document"),
            ("search", "_text", "(needle: str, encoding: str) -&gt; list[tuple[int, int]]", "document"),
            ("search", "_regex", "(pattern: str) -&gt; list[tuple[int, int]]", "document"),
            ("", "replace_bytes", "(find: bytes, replace: bytes) -&gt; int", "mutating"),
        ),
    ),
    (
        "Transforms",
        (
            ("", "transform_data", "(name: str, offset: int, length: int, params: dict[str, bytes]) -&gt; None", "mutating"),
            ("", "list_transforms", "() -&gt; list[tuple[str, str, str]]", "static"),
        ),
    ),
    (
        "Analysis",
        (
            ("", "content_classification", "(block_size: int) -&gt; bytes", "document"),
            ("", "digram_matrix", "() -&gt; list[int]", "document"),
            ("", "extract_strings", "(min_length: int) -&gt; list[dict[str, str]]", "document"),
        ),
    ),
)

_ARGUMENT_SPECIMENS: Final[tuple[tuple[str, str, str, str, str], ...]] = (
    ("INT", "offset", "int", "int", "Decimal, 0x hex or 0b binary."),
    ("FLOAT", "threshold", "float", "float", "Finite values only."),
    ("BOOL", "case_sensitive", "bool", "bool", "Sent as a JSON boolean."),
    ("TEXT", "encoding", "str", "select", "One of list_encodings()."),
    ("BYTES", "pattern", "bytes", "bytes", "Hex digits, whitespace ignored."),
    ("BYTES", "data", "bytes", "bytes_block", "Wraps and grows for whole records."),
    ("INT_PAIR", "window", "tuple[int, int]", "int_pair", "Start offset and length."),
    ("BOOL_PAIR", "flags", "tuple[bool, bool]", "bool_pair", "Two independent switches."),
    ("BYTES_MAP", "params", "dict[str, bytes]", "bytes_map", "Every value is raw bytes."),
    ("BOOKMARK", "bookmark", "Bookmark", "bookmark", "offset, length, label, colour."),
)

_ERROR_KINDS: Final[tuple[tuple[str, str, str, str], ...]] = (
    (
        "decode",
        "DECODE",
        "pattern: expected hexadecimal bytes, got '4d5ax0'",
        "Non-hex digit at index 4. Correct the argument and run again.",
    ),
    ("value", "VALUE", "length 65536 exceeds the remaining document size 1408", "ValueError raised by HexDocument.read_bytes."),
    ("index", "INDEX", "read_byte: offset 0x2A00 is past the end of the document", "IndexError. The document is 0x280 bytes long."),
    ("io", "I/O", "cannot open 'D:\\samples\\firmware.bin': the system cannot find the file", "OSError 2 raised by HexDocument.open."),
    ("busy", "BUSY", "the document is locked by transform_data, started 1.4 s ago", "Only one mutating operation runs at a time."),
    ("runtime", "RUNTIME", "process memory read failed for pid 8124 at 0x7FF6C21A0000", "RuntimeError raised by from_process_memory."),
    (
        "memory",
        "MEMORY",
        "reading 512 MiB would exceed the 128 MiB document memory budget",
        "Raise the ceiling with set_memory_budget_hint.",
    ),
    (
        "internal",
        "INTERNAL",
        "unhandled exception while dispatching 'apply_template'",
        "This is a hexbench defect. The traceback is in the server log.",
    ),
)

_TOAST_SPECIMENS: Final[tuple[tuple[str, str, str, str], ...]] = (
    ("success", "&#10003;", "Patch set exported", "kernel32.bps written, 4 records"),
    ("warning", "!", "Overlapping patches", "get_patches() returned 2 overlapping records"),
    ("error", "&times;", "Attach failed", "pid 8124 is not accessible from this session"),
    ("info", "i", "Snapshot only", "from_process_memory is a copy, not a live view"),
)

_RESULT_BANNERS: Final[tuple[tuple[str, str, str, str], ...]] = (
    ("success", "&#10003;", "Saved", "save_as('D:\\work\\kernel32.patched.dll') wrote 1462272 bytes"),
    ("info", "i", "No document required", "list_encodings() is a static method"),
    ("warning", "!", "Undo history reset", "import_patches_ups replaced the buffer and cleared file_path()"),
)

_RUN_STATES: Final[tuple[tuple[str, str, str, str], ...]] = (
    ("is-idle", "Run", "", "ready, nothing pending"),
    ("is-running", "Running", '<span class="hb-spinner"></span>', "request in flight"),
    ("is-done", "Done", "&#10003;", "completed, result below"),
    ("is-error", "Failed", "&times;", "raised, banner below"),
    ("is-mutating", "Run", "&#9679;", "will alter the document"),
)

_BUTTON_VARIANTS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("", "Secondary", False),
    ("is-primary", "Primary", False),
    ("is-ghost", "Ghost", False),
    ("is-danger", "Delete", False),
    ("", "Disabled", True),
)

_BOOKMARK_ROWS: Final[tuple[tuple[int, int, str, str], ...]] = (
    (0x0000003C, 4, "e_lfanew", "#4c9df0"),
    (0x000000F0, 4, "PE signature", "#4ec98a"),
    (0x0000014C, 2, "Subsystem", "#e3b341"),
    (0x000001F8, 8, ".text header", "#bd8ef2"),
)

_TEMPLATE_NODES: Final[tuple[tuple[int, str, str, str, str, bool, str, bool], ...]] = (
    (0, "IMAGE_DOS_HEADER", "struct", "64 bytes", "0x00000000", True, "--hb-accent", True),
    (1, "e_magic", "char[2]", "MZ", "0x00000000", False, "--hb-class-1", True),
    (1, "e_lfanew", "LONG", "0x000000F0", "0x0000003C", False, "--hb-class-1", True),
    (0, "IMAGE_NT_HEADERS64", "struct", "264 bytes", "0x000000F0", True, "--hb-accent", True),
    (1, "Signature", "DWORD", "PE\\0\\0", "0x000000F0", False, "--hb-class-1", True),
    (1, "FileHeader", "struct", "20 bytes", "0x000000F4", True, "--hb-class-2", True),
    (2, "Machine", "WORD", "IMAGE_FILE_MACHINE_AMD64", "0x000000F4", False, "--hb-class-1", True),
    (2, "NumberOfSections", "WORD", "6", "0x000000F6", False, "--hb-class-1", True),
    (2, "Characteristics", "WORD", "EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE", "0x00000106", False, "--hb-class-4", True),
    (1, "OptionalHeader", "struct", "240 bytes", "0x00000108", True, "--hb-class-2", True),
    (2, "Magic", "WORD", "PE32+", "0x00000108", False, "--hb-class-1", True),
    (2, "AddressOfEntryPoint", "DWORD", "0x00013F60", "0x00000118", False, "--hb-class-1", True),
    (2, "ImageBase", "ULONGLONG", "0x0000000140000000", "0x00000120", False, "--hb-class-1", True),
    (2, "CheckSum", "DWORD", "0x00000000", "0x00000148", False, "--hb-class-3", False),
    (2, "Subsystem", "WORD", "IMAGE_SUBSYSTEM_WINDOWS_CUI", "0x0000014C", False, "--hb-class-1", True),
)

_STRING_ROWS: Final[tuple[tuple[int, int, str, str], ...]] = (
    (0x0000004E, 39, "ascii", "This program cannot be run in DOS mode."),
    (0x000000C8, 4, "ascii", "Rich"),
    (0x000001F8, 5, "ascii", ".text"),
    (0x00000220, 6, "ascii", ".rdata"),
    (0x00000248, 5, "ascii", ".data"),
    (0x00000270, 6, "ascii", ".pdata"),
)

_STRING_CUTOFF: Final = 5
_UNDER_CUTOFF: Final = sum(1 for row in _STRING_ROWS if row[1] < _STRING_CUTOFF)

_SEARCH_ROWS: Final[tuple[tuple[int, str, str], ...]] = (
    (0x000001F8, ".text", "2e 74 65 78 74"),
    (0x00000220, ".rdata", "2e 72 64 61 74 61"),
    (0x00000248, ".data", "2e 64 61 74 61"),
    (0x00000270, ".pdata", "2e 70 64 61 74 61"),
)

_PATCH_ROWS: Final[tuple[tuple[int, str, str, bool], ...]] = (
    (0x0000014C, "03 00", "02 00", False),
    (0x0000014C, "02 00", "03 00", True),
    (0x00000148, "00 00 00 00", "1a 2b 3c 4d", False),
    (0x0000014A, "00 00", "5e 6f", True),
)

_VA_ROWS: Final[tuple[tuple[int, int, int, str, str, str], ...]] = (
    (0x00000600, 0x140001000, 0x00016A00, ".text", "R-X", "C:\\Program Files\\Intellicrack\\bin\\intellicrack_hexcore.pyd"),
    (0x00017000, 0x140018000, 0x0000A200, ".rdata", "R--", "C:\\Program Files\\Intellicrack\\bin\\intellicrack_hexcore.pyd"),
    (0x00021200, 0x140023000, 0x00000A00, ".data", "RW-", "C:\\Program Files\\Intellicrack\\bin\\intellicrack_hexcore.pyd"),
    (0x00021C00, 0x140033000, 0x00000600, ".pdata", "R--", "C:\\Program Files\\Intellicrack\\bin\\intellicrack_hexcore.pyd"),
)

_EMPTY_STATES: Final[tuple[tuple[str, str, str], ...]] = (
    ("&#9633;", "No document open", "Open a file, paste bytes, or attach to a process to begin."),
    ("&#9675;", "No bookmarks yet", "Select a range in the editor and press Ctrl+B to mark it."),
    ("&#9679;", "inspect_at returned nothing", "The caret is at or past the end of the document, so no readings are defined."),
)

_SCALAR_RESULTS: Final[tuple[tuple[str, str, str], ...]] = (
    ("can_undo()", "true", "hb-json-bool"),
    ("get_document_memory_usage()", "1462272", "hb-json-num"),
    ("compute_hash('sha256')", '"9f2c4e1a...b70d"', "hb-json-str"),
    ("file_path()", "null", "hb-json-null"),
)

_MONO_SPECIMEN: Final[tuple[tuple[str, str], ...]] = (
    ("lg", "0123456789 ABCDEF abcdef"),
    ("md", "0O0O0O 1lI1lI 5S5S 8B8B 2Z2Z"),
    ("sm", "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00"),
    ("sm", "!&quot;#$%&amp;'()*+,-./:;&lt;=&gt;?@[\\]^_`{|}~"),
)

_TRANSFORM_SELECT: Final = (
    '<select class="hb-select"><option>xor_repeating</option><option>aes_ecb_decrypt</option><option>zlib_inflate</option></select>'
)
_TRANSFORM_OFFSET: Final = '<input class="hb-input is-mono" value="0x00000600" aria-label="offset">'
_TRANSFORM_LENGTH: Final = '<input class="hb-input is-mono" value="0x00016A00" aria-label="length">'

_SAMPLE_JSON: Final[_Json] = {
    "name": "IMAGE_DOS_HEADER",
    "offset": 0,
    "size": 64,
    "validation_passed": True,
    "color": "#4c9df0",
    "children": [
        {
            "name": "e_magic",
            "offset": 0,
            "size": 2,
            "display_value": "MZ",
            "raw_bytes": {"__bytes__": "4d5a", "length": 2, "truncated": False},
        },
        {
            "name": "e_lfanew",
            "offset": 60,
            "size": 4,
            "display_value": "0x000000F0",
            "raw_bytes": {"__bytes__": "f0000000", "length": 4, "truncated": False},
        },
    ],
    "description": None,
    "entropy": 2.4581,
}

_COLLAPSED_KEYS: Final = frozenset({"children", "raw_bytes"})

_CHROME_CSS: Final = """
.ds-body {
  padding: var(--hb-space-8) var(--hb-space-9) var(--hb-space-11);
  background: var(--hb-surface-0);
}
.ds-head {
  max-width: 1180px;
  margin: 0 auto var(--hb-space-8);
  padding-bottom: var(--hb-space-5);
  border-bottom: 1px solid var(--hb-border);
}
.ds-eyebrow {
  font-size: var(--hb-fs-2xs);
  font-weight: var(--hb-fw-semibold);
  letter-spacing: var(--hb-tracking-caps);
  text-transform: uppercase;
  color: var(--hb-accent);
}
.ds-title {
  margin-top: var(--hb-space-2);
  font-size: var(--hb-fs-2xl);
  font-weight: var(--hb-fw-semibold);
  letter-spacing: var(--hb-tracking-tight);
  color: var(--hb-text-primary);
}
.ds-main { max-width: 1180px; margin: 0 auto; display: flex; flex-direction: column; gap: var(--hb-space-10); }
.ds-section { display: flex; flex-direction: column; gap: var(--hb-space-5); }
.ds-section-title {
  font-size: var(--hb-fs-xs);
  font-weight: var(--hb-fw-semibold);
  letter-spacing: var(--hb-tracking-caps);
  text-transform: uppercase;
  color: var(--hb-text-secondary);
}
.ds-section-note {
  margin-top: var(--hb-space-2);
  font-size: var(--hb-fs-sm);
  color: var(--hb-text-faint);
  max-width: 82ch;
  line-height: var(--hb-lh-normal);
}
.ds-section-note code {
  padding: 0 3px;
  border-radius: var(--hb-radius-xs);
  background: var(--hb-surface-code);
  color: var(--hb-text-secondary);
}
.ds-section-body { display: flex; flex-direction: column; gap: var(--hb-space-5); }
.ds-frame {
  border: 1px solid var(--hb-border);
  border-radius: var(--hb-radius-md);
  background: var(--hb-surface-1);
  overflow: hidden;
}
.ds-frame-label {
  padding: var(--hb-space-2) var(--hb-space-5);
  background: var(--hb-surface-2);
  border-bottom: 1px solid var(--hb-border-subtle);
  font-size: var(--hb-fs-2xs);
  font-weight: var(--hb-fw-semibold);
  letter-spacing: var(--hb-tracking-caps);
  text-transform: uppercase;
  color: var(--hb-text-faint);
}
.ds-frame-body { padding: var(--hb-space-6); }
.ds-frame-body.ds-flush { padding: 0; }
.ds-grid { display: grid; gap: var(--hb-space-5); grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); }
.ds-grid.is-wide { grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); }
.ds-grid.is-narrow { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
.ds-pair { display: grid; gap: var(--hb-space-6); grid-template-columns: repeat(auto-fit, minmax(430px, 1fr)); }
.ds-themecol {
  padding: var(--hb-space-6);
  background: var(--hb-surface-0);
  border: 1px solid var(--hb-border);
  border-radius: var(--hb-radius-md);
  overflow: hidden;
}
.ds-themecol-title {
  margin-bottom: var(--hb-space-5);
  font-size: var(--hb-fs-2xs);
  font-weight: var(--hb-fw-semibold);
  letter-spacing: var(--hb-tracking-caps);
  text-transform: uppercase;
  color: var(--hb-text-muted);
}
.ds-tokengroup { margin-bottom: var(--hb-space-6); }
.ds-tokengroup-title {
  margin-bottom: var(--hb-space-3);
  font-size: var(--hb-fs-2xs);
  letter-spacing: var(--hb-tracking-wide);
  text-transform: uppercase;
  color: var(--hb-text-faint);
}
.ds-token { display: flex; align-items: center; gap: var(--hb-space-4); height: 22px; }
.ds-token-chip {
  width: 34px; height: 15px; flex: 0 0 auto;
  border-radius: var(--hb-radius-xs);
  border: 1px solid var(--hb-border-strong);
  background-image: repeating-conic-gradient(var(--hb-surface-2) 0% 25%, var(--hb-surface-1) 0% 50%);
  background-size: 8px 8px;
}
.ds-token-chip span { display: block; width: 100%; height: 100%; border-radius: 1px; }
.ds-token-name { font-family: var(--hb-font-mono); font-size: var(--hb-fs-xs); color: var(--hb-text-secondary); }
.ds-item { display: flex; flex-direction: column; gap: var(--hb-space-3); }
.ds-caption { font-family: var(--hb-font-mono); font-size: var(--hb-fs-xs); color: var(--hb-text-faint); }
.ds-caption strong { color: var(--hb-text-secondary); font-weight: var(--hb-fw-semibold); }
.ds-cellgrid { display: grid; gap: var(--hb-space-4) var(--hb-space-6); grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); }
.ds-cellspec { display: flex; align-items: center; gap: var(--hb-space-4); }
.ds-cellspec-demo {
  display: flex; align-items: center; flex: 0 0 auto;
  padding: var(--hb-space-2) var(--hb-space-3);
  background: var(--hb-surface-1);
  border: 1px solid var(--hb-border-subtle);
  border-radius: var(--hb-radius-sm);
  font-family: var(--hb-font-mono);
  font-size: var(--hb-hex-fs);
}
.ds-cellspec-text { display: flex; flex-direction: column; min-width: 0; }
.ds-cellspec-name { font-size: var(--hb-fs-sm); color: var(--hb-text-primary); }
.ds-cellspec-note { font-size: var(--hb-fs-xs); color: var(--hb-text-faint); }
.ds-spacebar { height: 12px; border-radius: var(--hb-radius-xs); background: var(--hb-accent); }
.ds-elev { height: 70px; border-radius: var(--hb-radius-md); background: var(--hb-surface-1); border: 1px solid var(--hb-border-subtle); }
.ds-radius { height: 54px; background: var(--hb-accent-subtle); border: 1px solid var(--hb-accent-muted); }
.ds-specimen { font-family: var(--hb-font-mono); color: var(--hb-text-primary); }
.ds-overlaystage {
  position: relative;
  min-height: 430px;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: var(--hb-space-9) var(--hb-space-6);
  background: var(--hb-surface-1);
  background-image: repeating-linear-gradient(135deg, var(--hb-hatch-ink) 0 8px, transparent 8px 16px);
}
.ds-overlaystage .hb-scrim { position: absolute; }
.ds-stack { display: flex; flex-direction: column; gap: var(--hb-space-4); }
"""


@dataclass(frozen=True, slots=True)
class _Card:
    """One generated preview card.

    Attributes:
        filename: File name written into the cards directory.
        group: Gallery group recorded in the ``@dsCard`` marker.
        title: Human readable card title.
        body: Rendered HTML for the card body.
    """

    filename: str
    group: str
    title: str
    body: str


def sample_bytes() -> bytes:
    """Decode the built-in 64-bit PE header used as sample data.

    Returns:
        bytes: A 640 byte buffer holding a realistic PE image header.
    """
    return bytes.fromhex("".join(_SAMPLE_ROWS))


_SAMPLE: Final = sample_bytes()


def _packed_bytes(count: int) -> bytes:
    """Generate a deterministic high-entropy run.

    A 64-bit linear congruential generator stands in for a packed or encrypted
    section. The output is reproducible across runs, so the derived figures stay
    stable, while carrying genuine near-maximal entropy rather than a fabricated
    number.

    Args:
        count: Number of bytes to produce.

    Returns:
        bytes: Exactly ``count`` pseudo-random bytes.
    """
    out = bytearray()
    state = _PACKED_SEED
    while len(out) < count:
        state = (state * _LCG_MULTIPLIER + _LCG_INCREMENT) & _LCG_MASK
        out.extend((state >> _LCG_DISCARD).to_bytes(_LCG_CHUNK, "little"))
    return bytes(out[:count])


def _code_bytes(count: int) -> bytes:
    """Build a run of plausible x86-64 instruction bytes.

    Args:
        count: Number of bytes to produce.

    Returns:
        bytes: Exactly ``count`` bytes of moderate-entropy code-like content.
    """
    out = bytearray()
    filler = _packed_bytes(count)
    while len(out) < count:
        pattern = _CODE_PATTERNS[len(out) % len(_CODE_PATTERNS)]
        out.extend(bytes.fromhex(pattern))
        out.append(filler[len(out) % count])
    return bytes(out[:count])


def _text_bytes(count: int) -> bytes:
    """Build a run of NUL separated ASCII strings.

    Args:
        count: Number of bytes to produce.

    Returns:
        bytes: Exactly ``count`` bytes of string-table-like content.
    """
    out = bytearray()
    while len(out) < count:
        out.extend(_TEXT_FRAGMENTS[len(out) % len(_TEXT_FRAGMENTS)].encode("ascii"))
        out.append(_NULL_BYTE)
    return bytes(out[:count])


def _analysis_bytes() -> bytes:
    """Assemble the buffer the analysis figures are computed from.

    The 640 byte header alone is too small to exercise the entropy and
    classification scales: an eight byte window can carry at most three bits, so
    the high-entropy threshold would be unreachable by construction. This buffer
    continues the same image with the regions a real binary actually contains, so
    every classification code and the full 0 to 8 bit entropy range appear.

    Returns:
        bytes: A 16384 byte buffer beginning with the real PE header.
    """
    return b"".join((
        _SAMPLE,
        bytes(_PAD_AFTER_HEADER),
        _code_bytes(_CODE_LENGTH),
        _text_bytes(_TEXT_LENGTH),
        bytes(_GAP_LENGTH),
        _packed_bytes(_PACKED_LENGTH),
    ))


_ANALYSIS: Final = _analysis_bytes()


def _byte_class(value: int) -> str:
    """Classify a byte for the editor tinting scheme.

    Args:
        value: Byte value in the range 0 to 255.

    Returns:
        str: One of ``bc-null``, ``bc-print``, ``bc-ctrl`` or ``bc-high``.
    """
    if value == _NULL_BYTE:
        return "bc-null"
    if _PRINT_LOW <= value <= _PRINT_HIGH:
        return "bc-print"
    if value >= _HIGH_LOW:
        return "bc-high"
    return "bc-ctrl"


def _ascii_glyph(value: int) -> str:
    """Render a byte as its printable ASCII glyph or a placeholder.

    Args:
        value: Byte value in the range 0 to 255.

    Returns:
        str: HTML-escaped single character.
    """
    if _PRINT_LOW <= value <= _PRINT_HIGH:
        return escape(chr(value))
    return "."


def _entropy(chunk: bytes) -> float:
    """Compute the Shannon entropy of a byte run in bits per byte.

    Args:
        chunk: Bytes to measure.

    Returns:
        float: Entropy between 0.0 and 8.0, or 0.0 for an empty run.
    """
    if not chunk:
        return 0.0
    total = len(chunk)
    return -sum((count / total) * math.log2(count / total) for count in Counter(chunk).values())


def _inspector_rows() -> tuple[tuple[str, str, bool], ...]:
    """Decode the inspector table rows from the real sample header bytes.

    Every reading interprets the leading window of ``_SAMPLE`` with the same
    byte order and format the referenced type actually uses, so the panel
    never shows a value that disagrees with the bytes it claims to describe.

    Returns:
        tuple[tuple[str, str, bool], ...]: Rows of key, formatted value and
        whether the reading is a non-decodable placeholder.
    """
    window = _SAMPLE[:16]
    uint16_le: int = struct.unpack_from("<H", window)[0]
    red5, green6, blue5 = (uint16_le >> 11) & 0x1F, (uint16_le >> 5) & 0x3F, uint16_le & 0x1F
    float32: float = struct.unpack_from("<f", window)[0]
    float64: float = struct.unpack_from("<d", window)[0]
    unix_seconds: int = struct.unpack_from("<I", window)[0]
    return (
        ("int8", str(struct.unpack_from("<b", window)[0]), False),
        ("uint8", str(window[0]), False),
        ("int16_le", str(struct.unpack_from("<h", window)[0]), False),
        ("int16_be", str(struct.unpack_from(">h", window)[0]), False),
        ("rgb565", f"#{round(red5 * 255 / 0x1F):02x}{round(green6 * 255 / 0x3F):02x}{round(blue5 * 255 / 0x1F):02x}", False),
        ("dos_date", f"{1980 + ((uint16_le >> 9) & 0x7F)}-{(uint16_le >> 5) & 0x0F:02d}-{uint16_le & 0x1F:02d}", False),
        ("dos_time", f"{(uint16_le >> 11) & 0x1F:02d}:{(uint16_le >> 5) & 0x3F:02d}:{(uint16_le & 0x1F) * 2:02d}", False),
        ("float32", f"{float32:.4e}", False),
        ("rgba8", f"rgba({window[0]}, {window[1]}, {window[2]}, {window[3]})", False),
        ("ipv4", ".".join(str(value) for value in window[:4]), False),
        ("unix_timestamp", datetime.fromtimestamp(unix_seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), False),
        ("float64", f"{float64:.4e}", False),
        ("filetime", "1601-01-01T00:00:00Z", True),
        ("guid", str(uuid.UUID(bytes_le=window)), False),
        ("wide_string", "not decodable at this offset", True),
    )


_STATUS_ITEMS: Final[tuple[tuple[str, str, str], ...]] = (
    ("offset", "0x0000004A", ""),
    ("selection", "0x040 to 0x04D (14)", ""),
    ("size", "640 B", ""),
    ("entropy", f"{_entropy(_SAMPLE):.2f}", "is-accent"),
    ("patches", "4 unmerged", "is-warning"),
)

_INSPECTOR_ROWS: Final[tuple[tuple[str, str, bool], ...]] = _inspector_rows()


def _classify(chunk: bytes) -> int:
    """Assign a content classification code to a block, mirroring the engine.

    Args:
        chunk: Bytes of one classification block.

    Returns:
        int: 0 zero-filled, 1 plaintext-like, 2 moderate, 3 high entropy,
        4 mixed entropy.
    """
    if not any(chunk):
        return 0
    measured = _entropy(chunk)
    printable = sum(1 for value in chunk if _byte_class(value) in {"bc-print", "bc-null"})
    if printable >= len(chunk) * _TEXT_SHARE and measured < _MID_ENTROPY:
        return 1
    if measured > _HIGH_ENTROPY:
        return 3
    if measured >= _MID_ENTROPY:
        return 4
    return 2


def _edge_classes(classes: str, offset: int, start: int, end: int) -> str:
    """Derive the run-boundary classes for one offset inside a region.

    Args:
        classes: Class string declared for the region.
        offset: Offset being rendered.
        start: First offset of the region.
        end: Last offset of the region.

    Returns:
        str: Space separated boundary classes, empty when the offset is
        interior or the region has no boundary treatment.
    """
    parts: list[str] = []
    if "is-field" in classes:
        if offset == start:
            parts.append("is-field-start")
        if offset == end:
            parts.append("is-field-end")
    if "is-hit" in classes and offset == start:
        parts.append("is-hit-start")
    return " ".join(parts)


def _region_marks() -> dict[int, str]:
    """Expand the declared sample regions into per-offset class strings.

    Returns:
        dict[int, str]: Mapping of file offset to the extra classes that byte
        cell carries in the sample view.
    """
    marks: dict[int, str] = {}
    for start, end, classes in _SAMPLE_REGIONS:
        for offset in range(start, end + 1):
            edges = _edge_classes(classes, offset, start, end)
            marks[offset] = " ".join(part for part in (marks.get(offset, ""), classes, edges) if part)
    marks[_SAMPLE_CARET] = f"{marks.get(_SAMPLE_CARET, '')} is-caret is-nibble-right".strip()
    return marks


_SAMPLE_MARKS: Final = _region_marks()


def _cell_classes(base: str, value: int, extra: str, index: int) -> str:
    """Compose the full class attribute for one byte or ASCII cell.

    Args:
        base: Either ``hb-byte`` or ``hb-ascii``.
        value: Byte value being rendered.
        extra: State classes for this offset.
        index: Column index within the row, used for group spacing.

    Returns:
        str: Space separated class list.
    """
    grouped = base == "hb-byte" and index % _GROUP_SIZE == _GROUP_SIZE - 1 and index != _ROW_WIDTH - 1
    parts = (base, _byte_class(value), extra, "is-group-end" if grouped else "")
    return " ".join(part for part in parts if part)


def _row_is_marked(offset: int, length: int) -> bool:
    """Report whether any byte of a row carries a bookmark.

    Args:
        offset: File offset of the first byte of the row.
        length: Number of bytes in the row.

    Returns:
        bool: True when at least one byte in the row is bookmarked.
    """
    return any("is-bookmarked" in _SAMPLE_MARKS.get(offset + index, "") for index in range(length))


def _hex_row(offset: int, chunk: bytes) -> str:
    """Render one editor row with offset gutter, hex pane and ASCII pane.

    Args:
        offset: File offset of the first byte of the row.
        chunk: Up to 16 bytes to render.

    Returns:
        str: HTML for a single ``hb-row``.
    """
    hex_cells = "".join(
        f'<span class="{_cell_classes("hb-byte", value, _SAMPLE_MARKS.get(offset + index, ""), index)}">{value:02X}</span>'
        for index, value in enumerate(chunk)
    )
    ascii_cells = "".join(
        f'<span class="{_cell_classes("hb-ascii", value, _SAMPLE_MARKS.get(offset + index, ""), index)}">{_ascii_glyph(value)}</span>'
        for index, value in enumerate(chunk)
    )
    row_class = "hb-row is-current" if offset == _SAMPLE_CURRENT_ROW else "hb-row"
    gutter = "hb-offset is-marked" if _row_is_marked(offset, len(chunk)) else "hb-offset"
    return (
        f'<div class="{row_class}"><span class="{gutter}">{offset:08X}</span>'
        f'<span class="hb-hexpane">{hex_cells}</span>'
        f'<span class="hb-asciipane">{ascii_cells}</span></div>'
    )


def _ruler_column(index: int) -> str:
    """Render one column label of the editor ruler.

    Args:
        index: Column index from 0 to 15.

    Returns:
        str: HTML for one ``hb-ruler-col``.
    """
    grouped = " is-group-end" if index % _GROUP_SIZE == _GROUP_SIZE - 1 and index != _ROW_WIDTH - 1 else ""
    current = " is-current" if index == _SAMPLE_CARET % _ROW_WIDTH else ""
    return f'<span class="hb-ruler-col{grouped}{current}">{index:02X}</span>'


def _ruler() -> str:
    """Render the editor column ruler.

    Returns:
        str: HTML for the ``hb-ruler`` element.
    """
    columns = "".join(_ruler_column(index) for index in range(_ROW_WIDTH))
    return (
        '<div class="hb-ruler"><span class="hb-ruler-gutter">OFFSET</span>'
        f'<span class="hb-ruler-cols">{columns}</span>'
        '<span class="hb-ruler-ascii">ASCII</span></div>'
    )


def _rows_html(offsets: tuple[int, ...]) -> str:
    """Render a set of editor rows by their starting offsets.

    Args:
        offsets: Row start offsets to render.

    Returns:
        str: Concatenated HTML for the requested rows.
    """
    return "".join(_hex_row(offset, _SAMPLE[offset : offset + _ROW_WIDTH]) for offset in offsets)


def _hex_view(rows: int, *, static: bool = True) -> str:
    """Render the sample hex view for a number of leading rows.

    Args:
        rows: How many 16 byte rows to include.
        static: Whether the row list renders at full height instead of scrolling.

    Returns:
        str: HTML for a complete ``hb-editor`` element.
    """
    body = _rows_html(tuple(index * _ROW_WIDTH for index in range(rows)))
    mode = "hb-rows is-static" if static else "hb-rows"
    return f'<div class="hb-editor">{_ruler()}<div class="{mode}">{body}</div></div>'


def _demo_cell(value: int, classes: str) -> str:
    """Render a standalone byte cell specimen inside a demo frame.

    Args:
        value: Byte value to display.
        classes: Extra state classes.

    Returns:
        str: HTML for one framed ``hb-byte`` span.
    """
    full = " ".join(part for part in ("hb-byte", _byte_class(value), classes) if part)
    return f'<span class="ds-cellspec-demo"><span class="{full}">{value:02X}</span></span>'


def _cell_spec(value: int, classes: str, name: str, note: str) -> str:
    """Render a labelled byte cell specimen.

    Args:
        value: Byte value to display.
        classes: Extra state classes.
        name: Specimen name.
        note: Short explanatory note, inserted as markup.

    Returns:
        str: HTML for one specimen row.
    """
    return (
        f'<div class="ds-cellspec">{_demo_cell(value, classes)}'
        f'<span class="ds-cellspec-text"><span class="ds-cellspec-name">{escape(name)}</span>'
        f'<span class="ds-cellspec-note">{note}</span></span></div>'
    )


def _section(title: str, note: str, content: str) -> str:
    """Wrap content in a titled card section.

    Args:
        title: Section title.
        note: Supporting sentence beneath the title, inserted as markup.
        content: Rendered HTML for the section body.

    Returns:
        str: HTML for one ``ds-section``.
    """
    return (
        f'<section class="ds-section"><header><h2 class="ds-section-title">{escape(title)}</h2>'
        f'<p class="ds-section-note">{note}</p></header>'
        f'<div class="ds-section-body">{content}</div></section>'
    )


def _frame(label: str, content: str, *, flush: bool = False) -> str:
    """Wrap a specimen in a labelled frame.

    Args:
        label: Frame label.
        content: Rendered HTML for the frame body.
        flush: Whether the body should have no padding.

    Returns:
        str: HTML for one ``ds-frame``.
    """
    body_class = "ds-frame-body ds-flush" if flush else "ds-frame-body"
    return f'<div class="ds-frame"><div class="ds-frame-label">{escape(label)}</div><div class="{body_class}">{content}</div></div>'


def _grid(items: str, modifier: str = "") -> str:
    """Wrap items in a responsive specimen grid.

    Args:
        items: Rendered HTML for the grid children.
        modifier: Optional grid modifier class.

    Returns:
        str: HTML for one ``ds-grid``.
    """
    return f'<div class="ds-grid {modifier}">{items}</div>'


def _token_column(theme: str) -> str:
    """Render every colour token group under an explicit theme.

    Args:
        theme: Either ``light`` or ``dark``.

    Returns:
        str: HTML for one theme column.
    """
    groups = "".join(
        f'<div class="ds-tokengroup"><div class="ds-tokengroup-title">{escape(name)}</div>'
        + "".join(
            f'<div class="ds-token"><span class="ds-token-chip"><span style="background: var({token})"></span></span>'
            f'<span class="ds-token-name">{escape(token)}</span></div>'
            for token in tokens
        )
        + "</div>"
        for name, tokens in _COLOUR_TOKENS
    )
    return f'<div class="ds-themecol" data-theme="{theme}"><div class="ds-themecol-title">{theme} theme</div>{groups}</div>'


def _card_colour_tokens() -> str:
    """Build the colour token foundations card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Colour system",
        "Both themes are authored independently. Dark is the working default for long analysis sessions; light is tuned for "
        "print and projection rather than derived by inverting the dark ramp. Every component reads only from these names, so a "
        "theme change is a token swap and nothing else.",
        f'<div class="ds-pair">{_token_column("light")}{_token_column("dark")}</div>',
    )


def _card_type_scale() -> str:
    """Build the type scale foundations card.

    Returns:
        str: Card body HTML.
    """
    rows = "".join(
        f'<div class="ds-item"><div style="font-size: var({token}); color: var(--hb-text-primary); line-height: 1.2">'
        "Sixteen bytes per row &middot; 0x00400000</div>"
        f'<div class="ds-caption"><strong>{escape(token)}</strong> &middot; {escape(size)} &middot; {escape(use)}</div></div>'
        for token, size, use in _TYPE_SCALE
    )
    weights = "".join(
        f'<div class="ds-item"><div style="font-weight: var(--hb-fw-{name}); font-size: var(--hb-fs-lg)">Import directory</div>'
        f'<div class="ds-caption">--hb-fw-{name}</div></div>'
        for name in _WEIGHTS
    )
    return _section(
        "Type scale",
        "One UI family and one monospace family. Sizes step at the density an analysis surface needs, with the two smallest "
        "reserved for column labels and status readings.",
        _frame("Sizes", _grid(rows, "is-wide")) + _frame("Weights", _grid(weights)),
    )


def _card_spacing() -> str:
    """Build the spacing and radius foundations card.

    Returns:
        str: Card body HTML.
    """
    bars = "".join(
        f'<div class="ds-item"><div class="ds-spacebar" style="width: var({token})"></div>'
        f'<div class="ds-caption"><strong>{escape(token)}</strong> &middot; {size}px</div></div>'
        for token, size in _SPACE_SCALE
    )
    radii = "".join(
        f'<div class="ds-item"><div class="ds-radius" style="border-radius: var({token})"></div>'
        f'<div class="ds-caption"><strong>{escape(token)}</strong> &middot; {escape(size)}</div></div>'
        for token, size in _RADII
    )
    return _section(
        "Spacing and radius",
        "A 2px base with a compressing ramp. Chrome lives in steps 1 to 5; only page-level composition reaches step 9 and above.",
        _frame("Spacing scale", _grid(bars, "is-narrow")) + _frame("Radii", _grid(radii, "is-narrow")),
    )


def _card_elevation() -> str:
    """Build the elevation foundations card.

    Returns:
        str: Card body HTML.
    """
    boxes = "".join(
        f'<div class="ds-item"><div class="ds-elev" style="box-shadow: var({token})"></div>'
        f'<div class="ds-caption"><strong>{escape(token)}</strong> &middot; {escape(use)}</div></div>'
        for token, use in _ELEVATIONS
    )
    return _section(
        "Elevation",
        "Shadows are theme-specific: soft and cool in light, deep and near-black in dark, so a popover reads as lifted in both.",
        _frame("Shadow scale", _grid(boxes)),
    )


def _card_mono_specimen() -> str:
    """Build the monospace specimen foundations card.

    Returns:
        str: Card body HTML.
    """
    body = "".join(f'<div class="ds-specimen" style="font-size: var(--hb-fs-{size})">{line}</div>' for size, line in _MONO_SPECIMEN)
    return _section(
        "Monospace stack",
        "All byte data uses <code>&quot;Cascadia Mono&quot;, &quot;Cascadia Code&quot;, Consolas, &quot;Segoe UI Mono&quot;, "
        "monospace</code> with ligatures and contextual alternates disabled, so <code>!=</code> never fuses and every column is "
        "exactly one advance wide. Numerals are tabular throughout.",
        _frame("Specimen", f'<div class="hb-stack">{body}</div>') + _frame("Tabular alignment in the editor", _hex_view(3), flush=True),
    )


def _card_byte_states() -> str:
    """Build the byte cell state card.

    Returns:
        str: Card body HTML.
    """
    classes_demo = "".join(_cell_spec(value, "", label, note) for _, label, note, value in _BYTE_CLASSES)
    states = "".join(_cell_spec(0x4D, classes, name, escape(note)) for classes, name, note in _CELL_STATES)
    combos = "".join(_cell_spec(0x5A, classes, name, "layered slots stay legible") for classes, name in _CELL_COMBOS)
    return (
        _section(
            "Byte class tinting",
            "Class tinting is the lowest layer. It colours the glyph and adds a barely-there wash, so structure is visible "
            "without competing with any editing state drawn on top of it.",
            _frame("Four classes", f'<div class="ds-cellgrid">{classes_demo}</div>'),
        )
        + _section(
            "States",
            "Each state writes into its own custom-property slot on the cell, so the layers composite instead of overwriting one another.",
            _frame("Single states", f'<div class="ds-cellgrid">{states}</div>'),
        )
        + _section(
            "Composition",
            "Region backgrounds blend, edge markers occupy different edges, and the caret is drawn last with a contrast ring so "
            "it survives every combination.",
            _frame("Combined states", f'<div class="ds-cellgrid">{combos}</div>'),
        )
    )


def _card_row_and_ruler() -> str:
    """Build the hex row, gutter and ruler card.

    Returns:
        str: Card body HTML.
    """
    excerpt = f'<div class="hb-editor"><div class="hb-rows is-static">{_rows_html((0x030, 0x040, 0x050))}</div></div>'
    return _section(
        "Column ruler and offset gutter",
        "The ruler is sticky and marks the caret column. The gutter switches to the bookmark colour when the row carries one, "
        "so a marked offset is findable while scrolling without widening the gutter.",
        _frame("Ruler plus four rows", _hex_view(4), flush=True),
    ) + _section(
        "Group spacing",
        "An extra 7px gap after every eighth byte gives the eye an anchor without a rule and without a second colour.",
        _frame("Rows 0x030, 0x040 and 0x050", excerpt, flush=True),
    )


def _card_sample_view() -> str:
    """Build the full sample hex view card.

    Returns:
        str: Card body HTML.
    """
    dark = f'<div class="ds-themecol" data-theme="dark"><div class="ds-themecol-title">dark theme</div>{_hex_view(40)}</div>'
    light = f'<div class="ds-themecol" data-theme="light"><div class="ds-themecol-title">light theme</div>{_hex_view(40)}</div>'
    return _section(
        "Forty rows against a real PE header",
        "The sample is the first 640 bytes of a 64-bit PE image: DOS header, DOS stub, Rich header, the PE signature at 0x0F0, "
        "the COFF and optional headers, and the start of the section table. A selection, a nibble caret, a bookmark, modified "
        "bytes, three template fields, three search hits and two diff regions are all live at once.",
        f'<div class="ds-pair">{dark}{light}</div>',
    )


def _card_busy() -> str:
    """Build the busy hatch card.

    Returns:
        str: Card body HTML.
    """
    overlay = (
        f'<div style="position: relative">{_hex_view(8)}'
        '<div class="hb-busy" style="position: absolute; inset: var(--hb-row-h) 0 0 0">'
        '<div class="hb-busy-label"><span class="hb-spinner"></span>transform_data</div></div></div>'
    )
    stale = (
        '<div class="hb-panel is-framed"><div class="hb-panel-header">'
        '<span class="hb-panel-title">Entropy</span>'
        '<span class="hb-panel-subtitle">entropy_map(window=256)</span></div>'
        '<div class="hb-panel-body is-padded hb-hatch" style="min-height: 120px">'
        '<p class="hb-dim">The document changed under this reading. The panel keeps the previous curve legible beneath the '
        "hatch instead of blanking, because a stale answer is more useful than none while the recompute runs.</p></div></div>"
    )
    return _section(
        "Busy hatch",
        "A mutating operation covers the affected view with a drifting diagonal hatch rather than an opaque spinner overlay, so "
        "the underlying data stays readable while it is known to be stale. The drift stops under reduced motion.",
        _frame("Editor region while transform_data runs", overlay, flush=True),
    ) + _section(
        "Stale panel",
        "<code>hb-hatch</code> is the same texture without the overlay positioning, applied directly to any surface whose "
        "contents are known to be out of date. Here it sits on a padded panel body rather than an absolutely placed layer.",
        _frame("Panel awaiting recompute", stale),
    )


def _menu_entry(label: str, shortcut: str, *, enabled: bool) -> str:
    """Render one menu popup entry or a separator.

    Args:
        label: Entry text, empty for a separator.
        shortcut: Keyboard shortcut text.
        enabled: Whether the entry is selectable.

    Returns:
        str: HTML for one entry or separator.
    """
    if not label:
        return '<div class="hb-menu-sep"></div>'
    state = "" if enabled else " is-disabled"
    return (
        f'<button type="button" class="hb-menu-entry{state}">'
        f'<span class="hb-menu-entry-label">{escape(label)}</span>'
        f'<span class="hb-menu-shortcut">{escape(shortcut)}</span></button>'
    )


def _menubar(*, open_menu: bool = True) -> str:
    """Render the menu bar, optionally with the File popup open.

    Args:
        open_menu: Whether the File menu is shown expanded.

    Returns:
        str: HTML for the menu bar.
    """
    entries = "".join(_menu_entry(label, shortcut, enabled=enabled) for label, shortcut, enabled in _MENU_ENTRIES)
    others = "".join(f'<button type="button" class="hb-menu-item">{escape(name)}</button>' for name in _MENU_TITLES)
    popup = f'<div class="hb-menu-popup">{entries}</div>' if open_menu else ""
    state = " is-open" if open_menu else ""
    return (
        '<div class="hb-menubar"><div class="hb-menubar-brand"><span class="hb-menubar-mark"></span>HEXBENCH</div>'
        f'<div class="hb-menu"><button type="button" class="hb-menu-item{state}">File</button>'
        f"{popup}</div>{others}</div>"
    )


def _toolbar() -> str:
    """Render the main toolbar.

    Returns:
        str: HTML for the toolbar.
    """
    return (
        '<div class="hb-toolbar">'
        '<div class="hb-tool-group">'
        '<button type="button" class="hb-tool-btn"><span class="hb-tool-icon">&#9633;</span>Open</button>'
        '<button type="button" class="hb-tool-btn"><span class="hb-tool-icon">&#9635;</span>Save</button>'
        "</div>"
        '<div class="hb-tool-sep"></div>'
        '<div class="hb-tool-group">'
        '<button type="button" class="hb-tool-btn"><span class="hb-tool-icon">&#8630;</span>Undo</button>'
        '<button type="button" class="hb-tool-btn" disabled><span class="hb-tool-icon">&#8631;</span>Redo</button>'
        "</div>"
        '<div class="hb-tool-sep"></div>'
        '<div class="hb-tool-group">'
        '<button type="button" class="hb-tool-btn is-active"><span class="hb-tool-icon">&#9636;</span>Inspector</button>'
        '<button type="button" class="hb-tool-btn"><span class="hb-tool-icon">&#9639;</span>Templates</button>'
        '<button type="button" class="hb-tool-btn"><span class="hb-tool-icon">&#9638;</span>Entropy</button>'
        "</div>"
        '<div class="hb-tool-spacer"></div>'
        '<span class="hb-tool-label">Goto</span>'
        '<span class="hb-tool-field">0x<input class="hb-input is-mono is-narrow" value="000000F0" aria-label="Go to offset"></span>'
        '<div class="hb-tool-sep"></div>'
        '<button type="button" class="hb-tool-btn"><span class="hb-tool-icon">&#9881;</span>Settings</button>'
        "</div>"
    )


def _document_tab(name: str, *, active: bool, dirty: bool) -> str:
    """Render one document tab.

    Args:
        name: Document title.
        active: Whether this is the focused document.
        dirty: Whether the document has unsaved edits.

    Returns:
        str: HTML for one ``hb-tab``.
    """
    state = " is-active" if active else ""
    mark = '<span class="hb-tab-dirty" title="unsaved changes"></span>' if dirty else ""
    return (
        f'<div class="hb-tab{state}"><span class="hb-tab-icon">&#9679;</span>'
        f'<span class="hb-tab-title">{escape(name)}</span>{mark}'
        '<button type="button" class="hb-tab-close" aria-label="Close">&times;</button></div>'
    )


def _document_tabs() -> str:
    """Render the document tab strip.

    Returns:
        str: HTML for the tab strip.
    """
    tabs = "".join(_document_tab(name, active=active, dirty=dirty) for name, active, dirty in _DOCUMENT_TABS)
    return f'<div class="hb-tabstrip">{tabs}<div class="hb-tabstrip-overflow">+2</div></div>'


def _dock_tab(name: str, count: str, *, active: bool) -> str:
    """Render one dock tab.

    Args:
        name: Panel name.
        count: Item count, empty when the panel holds nothing countable.
        active: Whether the panel is showing.

    Returns:
        str: HTML for one ``hb-dock-tab``.
    """
    state = " is-active" if active else ""
    pill = f'<span class="hb-dock-tab-count">{escape(count)}</span>' if count else ""
    return f'<button type="button" class="hb-dock-tab{state}">{escape(name)}{pill}</button>'


def _dock_tabs(tabs: tuple[tuple[str, str, bool], ...]) -> str:
    """Render a dock tab strip.

    Args:
        tabs: Panel name, item count and active flag for each tab.

    Returns:
        str: HTML for the dock tab strip.
    """
    rendered = "".join(_dock_tab(name, count, active=active) for name, count, active in tabs)
    return f'<div class="hb-dock-tabs">{rendered}</div>'


def _statusbar() -> str:
    """Render the status bar.

    Returns:
        str: HTML for the status bar.
    """
    items = "".join(
        f'<span class="hb-status-item {extra}"><span class="hb-status-key">{escape(key)}</span>'
        f'<span class="hb-status-value">{escape(value)}</span></span><span class="hb-status-sep"></span>'
        for key, value, extra in _STATUS_ITEMS
    )
    return (
        f'<div class="hb-statusbar">{items}<span class="hb-status-grow"></span>'
        '<span class="hb-status-item"><span class="hb-status-dot is-ready"></span>'
        '<span class="hb-status-value">engine ready</span></span>'
        '<span class="hb-status-sep"></span>'
        '<span class="hb-status-item"><span class="hb-status-key">ops</span>'
        '<span class="hb-status-value">90 / 90</span></span></div>'
    )


def _palette_item(match: str, name: str, signature: str, tag: str, *, active: bool) -> str:
    """Render one command palette result row.

    Args:
        match: Leading matched characters, rendered emphasised.
        name: Remainder of the operation name.
        signature: Full call signature, already entity-escaped.
        tag: Receiver kind label.
        active: Whether this row is keyboard-highlighted.

    Returns:
        str: HTML for one ``hb-palette-item``.
    """
    state = " is-active" if active else ""
    matched = f'<span class="hb-match">{escape(match)}</span>' if match else ""
    return (
        f'<button type="button" class="hb-palette-item{state}"><span class="hb-palette-mark">&#9656;</span>'
        f'<span class="hb-palette-name">{matched}{escape(name)}</span>'
        f'<span class="hb-palette-sig">{signature}</span>'
        f'<span class="hb-palette-tag">{escape(tag)}</span></button>'
    )


def _palette() -> str:
    """Render the command palette overlay.

    Returns:
        str: HTML for the palette.
    """
    groups = "".join(
        f'<div class="hb-palette-group">{escape(group)}</div>'
        + "".join(_palette_item(match, name, signature, tag, active=name == "_bytes") for match, name, signature, tag in items)
        for group, items in _PALETTE_GROUPS
    )
    return (
        '<div class="hb-palette"><div class="hb-palette-field"><span class="hb-palette-glyph">&#8250;</span>'
        '<input class="hb-palette-input" value="search" aria-label="Command"></div>'
        f'<div class="hb-palette-results">{groups}</div>'
        '<div class="hb-palette-footer">'
        '<span><span class="hb-kbd">&#8593;</span><span class="hb-kbd">&#8595;</span> navigate</span>'
        '<span><span class="hb-kbd">&#8629;</span> run</span>'
        '<span><span class="hb-kbd">Esc</span> dismiss</span>'
        '<span class="hb-grow"></span><span>9 of 90 operations</span></div></div>'
    )


def _inspector_table() -> str:
    """Render the inspector key and value table.

    Returns:
        str: HTML for one ``hb-kv`` table.
    """
    rows = "".join(
        f'<tr><td class="hb-kv-key">{escape(key)}</td><td class="hb-kv-value{" is-dim" if dim else ""}">{escape(value)}</td></tr>'
        for key, value, dim in _INSPECTOR_ROWS
    )
    return f'<table class="hb-kv">{rows}</table>'


def _strings_table(*, by_length: bool = False) -> str:
    """Render the extracted strings table.

    Args:
        by_length: Whether to sort descending by length instead of ascending by
            offset, which also marks rows shorter than the display cutoff.

    Returns:
        str: HTML for one ``hb-table``.
    """
    entries = sorted(_STRING_ROWS, key=lambda row: -row[1]) if by_length else _STRING_ROWS
    badge = "hb-badge is-mono is-pill" if by_length else "hb-badge is-mono"
    rows = "".join(
        f'<tr class="{"is-muted" if by_length and length < _STRING_CUTOFF else ""}">'
        f'<td class="is-mono">0x{offset:08X}</td><td class="is-numeric">{length}</td>'
        f'<td><span class="{badge}">{escape(encoding)}</span></td>'
        f'<td class="is-wide is-mono is-primary">{escape(content)}</td></tr>'
        for offset, length, encoding, content in entries
    )
    offset_sort = "is-sortable" if by_length else "is-sortable is-sort-asc"
    length_sort = "is-sortable is-numeric is-sort-desc" if by_length else "is-sortable is-numeric"
    headers = (
        f'<th class="{offset_sort}">Offset</th><th class="{length_sort}">Len</th>'
        '<th class="is-sortable">Encoding</th><th class="is-wide">Content</th>'
    )
    return _table(headers, rows)


def _app_shell() -> str:
    """Render the complete application shell with both docks populated.

    Returns:
        str: HTML for one ``hb-app`` grid.
    """
    right = (
        f'<div class="hb-dock hb-dock-right">{_dock_tabs(_DOCK_TABS)}<div class="hb-dock-body hb-scroll">{_inspector_table()}</div></div>'
    )
    bottom = (
        f'<div class="hb-dock hb-dock-bottom">{_dock_tabs(_BOTTOM_DOCK_TABS)}'
        f'<div class="hb-dock-body hb-scroll">{_strings_table()}</div></div>'
    )
    workspace = (
        '<div class="hb-workspace">'
        f'<div class="hb-main">{_hex_view(_SHELL_ROWS, static=False)}</div>'
        '<div class="hb-splitter hb-splitter-v"></div>'
        '<div class="hb-splitter hb-splitter-h"></div>'
        f"{bottom}{right}</div>"
    )
    return (
        f'<div class="hb-app" style="height: {_SHELL_HEIGHT}px">'
        f"{_menubar(open_menu=False)}{_toolbar()}{_document_tabs()}{workspace}{_statusbar()}</div>"
    )


def _card_app_shell() -> str:
    """Build the composed application shell card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Application shell",
        "The whole chrome composed at once: menu bar, toolbar, document tabs, the editor, a right dock and a bottom dock either "
        "side of their splitters, and the status bar. The shell is a five row grid whose editor row is "
        "<code>minmax(0, 1fr)</code>, so the docks hold their size and only the editor absorbs the remaining height.",
        _frame("Full window", _app_shell(), flush=True),
    )


def _card_menubar() -> str:
    """Build the menu bar chrome card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Menu bar",
        "A 30px bar carrying the product mark, one open popup, right-aligned monospace shortcuts and a disabled entry.",
        _frame("File menu open", f'<div style="min-height: 380px">{_menubar()}</div>', flush=True),
    )


def _card_toolbar() -> str:
    """Build the toolbar chrome card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Toolbar",
        "Actions are grouped and separated by hairlines rather than by whitespace alone. The panel toggles show their state, "
        "unavailable actions stay in place disabled, and the goto field is monospace because it takes an address.",
        _frame("Primary toolbar", _toolbar(), flush=True),
    )


def _card_document_tabs() -> str:
    """Build the document tab card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Document tabs",
        "One tab per open HexDocument. The dot marks unsaved edits, a process-memory snapshot is titled by pid and base address, "
        "and the active tab is lifted onto the editor surface and underlined in accent.",
        _frame("Four documents open", _document_tabs(), flush=True),
    )


def _card_dock_tabs() -> str:
    """Build the dock tab and splitter card.

    Returns:
        str: Card body HTML.
    """
    splitters = (
        '<div style="display: flex; align-items: stretch; height: 90px; background: var(--hb-surface-1)">'
        '<div class="hb-grow"></div>'
        '<div class="hb-splitter hb-splitter-v" style="grid-area: auto; width: var(--hb-splitter-size)"></div>'
        '<div class="hb-grow"></div></div>'
        '<div class="hb-splitter hb-splitter-h" style="grid-area: auto; height: var(--hb-splitter-size)"></div>'
        '<div style="height: 60px; background: var(--hb-surface-1)"></div>'
    )
    dragging = (
        '<div style="display: flex; align-items: stretch; height: 90px; background: var(--hb-surface-1)">'
        '<div class="hb-grow"></div>'
        '<div class="hb-splitter hb-splitter-v is-dragging" style="grid-area: auto; width: var(--hb-splitter-size)"></div>'
        '<div class="hb-grow"></div></div>'
        '<div class="hb-splitter hb-splitter-h is-dragging" style="grid-area: auto; height: var(--hb-splitter-size)"></div>'
        '<div style="height: 60px; background: var(--hb-surface-1)"></div>'
    )
    return (
        _section(
            "Dock tabs",
            "Dock tabs are uppercase and carry a count pill whenever the panel holds a countable collection.",
            _frame(
                "Right dock",
                f'<div class="hb-dock hb-dock-right" style="border-left: 0">{_dock_tabs(_DOCK_TABS)}</div>',
                flush=True,
            ),
        )
        + _section(
            "Splitters",
            "Splitters are 5px hit targets that stay invisible until hovered, then reveal a short grip and an accent wash.",
            _frame("Vertical and horizontal", splitters, flush=True),
        )
        + _section(
            "Splitters while dragging",
            "<code>is-dragging</code> pins the hover treatment for the length of the drag, because the pointer is captured and "
            "will leave the 5px band long before the drag ends.",
            _frame("Both axes held down", dragging, flush=True),
        )
    )


def _card_statusbar() -> str:
    """Build the status bar chrome card.

    Returns:
        str: Card body HTML.
    """
    engine_states = "".join(
        f'<div class="hb-statusbar"><span class="hb-status-grow"></span>'
        f'<span class="hb-status-item hb-nowrap"><span class="hb-status-dot {state}"></span>'
        f'<span class="hb-sr-only">{escape(reading)}: </span>'
        f'<span class="hb-status-value">{escape(label)}</span></span></div>'
        for state, label, reading in _ENGINE_STATES
    )
    return _section(
        "Status bar",
        "Every reading is a labelled monospace pair, so values stay aligned as they change under the caret. Severity is carried "
        "by the state dot as well as by colour.",
        _frame("Status bar", _statusbar(), flush=True),
    ) + _section(
        "Engine state",
        "The dot is never the only carrier of the state: the adjacent word says the same thing, and a visually hidden "
        "<code>hb-sr-only</code> prefix names the reading for a screen reader that would otherwise hear a bare adjective.",
        _frame("Ready, working, failed", engine_states, flush=True),
    )


def _card_palette() -> str:
    """Build the command palette chrome card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Command palette",
        "All 90 engine operations are reachable here. Results are grouped by catalogue group, matched characters are emphasised, "
        "the keyboard-highlighted row is filled with accent, and every row shows the full signature and the receiver kind so the "
        "caller knows whether a document is needed and whether the call mutates.",
        _frame("Palette over the workspace", f'<div class="ds-overlaystage"><div class="hb-scrim"></div>{_palette()}</div>', flush=True),
    )


def _panel(title: str, subtitle: str, body: str, footer: str) -> str:
    """Render a framed panel.

    Args:
        title: Panel title.
        subtitle: Monospace subtitle shown beside the title.
        body: Rendered HTML for the panel body.
        footer: Rendered HTML for the panel footer, empty to omit it.

    Returns:
        str: HTML for one ``hb-panel``.
    """
    tail = f'<div class="hb-panel-footer">{footer}</div>' if footer else ""
    return (
        '<div class="hb-panel is-framed"><div class="hb-panel-header">'
        f'<span class="hb-panel-title">{escape(title)}</span>'
        f'<span class="hb-panel-subtitle">{escape(subtitle)}</span>'
        '<span class="hb-panel-actions">'
        '<button type="button" class="hb-panel-action is-active" title="Pin">&#9679;</button>'
        '<button type="button" class="hb-panel-action" title="Refresh">&#8635;</button>'
        '<button type="button" class="hb-panel-action" title="Close">&times;</button>'
        f'</span></div><div class="hb-panel-body">{body}</div>{tail}</div>'
    )


def _table(headers: str, rows: str) -> str:
    """Render a data table.

    Args:
        headers: Rendered ``th`` cells.
        rows: Rendered ``tr`` rows.

    Returns:
        str: HTML for one ``hb-table``.
    """
    return f'<table class="hb-table"><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table>'


def _card_panel_frame() -> str:
    """Build the panel frame and data table card.

    Returns:
        str: Card body HTML.
    """
    rows = "".join(
        f'<tr class="{"is-selected" if label == "PE signature" else ""}"><td class="is-mono">0x{offset:08X}</td>'
        f'<td class="is-numeric">{length}</td><td class="is-wide is-primary">{escape(label)}</td>'
        f'<td><span class="hb-swatch" style="background: {colour}"></span> <span class="hb-mono hb-dim">{colour}</span></td></tr>'
        for offset, length, label, colour in _BOOKMARK_ROWS
    )
    headers = (
        '<th class="is-sortable is-sort-asc">Offset</th><th class="is-sortable is-numeric">Length</th>'
        '<th class="is-wide is-sortable">Label</th><th>Colour</th>'
    )
    return _section(
        "Panel frame and table",
        "Uppercase title, monospace context subtitle, right-aligned icon actions, a scrolling body and a summary footer. The "
        "table has a sticky sortable header, zebra rows and a fixed row height so a virtualized list can reuse it unchanged.",
        _panel(
            "Bookmarks",
            "get_bookmarks()",
            _table(headers, rows),
            '<span>4 bookmarks</span><span class="hb-grow"></span><span class="hb-mono">add_bookmark_object()</span>',
        ),
    )


def _card_inspector() -> str:
    """Build the inspector panel card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Inspector",
        "The key set is whatever <code>inspect_at(offset)</code> returned and nothing else. Rows are never hardcoded: near the "
        "end of a document the wider types simply stop appearing, and past EOF the mapping is empty and the panel shows its "
        "empty state rather than a table of dashes.",
        _panel(
            "Inspector",
            "inspect_at(0x00000000)",
            _inspector_table(),
            '<span class="hb-mono">15 readings &middot; 640 bytes remaining</span>',
        ),
    )


def _template_node(depth: int, label: str, kind: str, value: str, offset: str, colour: str, *, parent: bool, valid: bool) -> str:
    """Render one template tree node.

    Args:
        depth: Nesting depth of the field.
        label: Field name.
        kind: Field type text.
        value: Display value.
        offset: Field offset, pre-formatted.
        colour: Custom property supplying the field colour bar.
        parent: Whether the field has children.
        valid: Whether validation passed for this field.

    Returns:
        str: HTML for one ``hb-tree-node``.
    """
    selected = " is-selected" if label == "Subsystem" else ""
    twisty = " is-open" if parent else " is-leaf"
    badge = "" if valid else '<span class="hb-badge is-error">FAILED</span>'
    return (
        f'<div class="hb-tree-node{selected}" style="--hb-tree-depth: {depth}">'
        '<span class="hb-tree-indent"></span>'
        f'<span class="hb-tree-twisty{twisty}"></span>'
        f'<span class="hb-tree-mark" style="background: var({colour})"></span>'
        f'<span class="hb-tree-label">{escape(label)}</span>'
        f'<span class="hb-tree-type">{escape(kind)}</span>'
        f'<span class="hb-tree-value">{escape(value)}</span>{badge}'
        f'<span class="hb-tree-offset">{escape(offset)}</span></div>'
    )


def _card_template_tree() -> str:
    """Build the template tree card.

    Returns:
        str: Card body HTML.
    """
    nodes = "".join(
        _template_node(depth, label, kind, value, offset, colour, parent=parent, valid=valid)
        for depth, label, kind, value, offset, parent, colour, valid in _TEMPLATE_NODES
    )
    return _section(
        "Template tree",
        "One node per dict returned by <code>apply_template</code>, nested through <code>children</code> to any depth. The colour "
        "bar comes from the field's own <code>color</code>, and a field whose <code>validation_passed</code> is false also gets an "
        "explicit FAILED badge, so the signal never depends on colour alone.",
        _panel(
            "Template",
            "apply_template('PE (64-bit)', 0)",
            f'<div class="hb-tree">{nodes}</div>',
            '<span class="hb-mono">15 of 48 fields &middot; 1 validation failure</span>',
        ),
    )


def _card_strings() -> str:
    """Build the extracted strings card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Strings",
        "<code>extract_strings</code> returns dicts of offset, length, encoding and content. Offset is the default sort key and "
        "the content column keeps the monospace face so embedded punctuation stays aligned.",
        _panel(
            "Strings",
            "extract_strings(min_length=4)",
            _strings_table(),
            '<span class="hb-mono">6 strings &middot; min length 4</span>',
        ),
    ) + _section(
        "Re-sorted and de-emphasised",
        "Clicking a second header moves the sort caret and flips it to <code>is-sort-desc</code>. Rows that survive the query but "
        "fall under the current display cutoff stay in place as <code>is-muted</code> rather than vanishing, so the count in the "
        "footer keeps matching what the engine returned.",
        _panel(
            "Strings",
            "extract_strings(min_length=4) sorted by length",
            _strings_table(by_length=True),
            f'<span class="hb-mono">{len(_STRING_ROWS)} strings &middot; {_UNDER_CUTOFF} under the {_STRING_CUTOFF} byte cutoff</span>',
        ),
    )


def _card_search_results() -> str:
    """Build the search results card.

    Returns:
        str: Card body HTML.
    """
    rows = "".join(
        f'<tr class="{"is-selected" if offset == _SEARCH_ROWS[0][0] else ""}"><td class="is-mono">0x{offset:08X}</td>'
        f'<td class="is-numeric">{len(raw.split())}</td><td class="is-mono">{escape(raw)}</td>'
        f'<td class="is-wide is-mono is-primary">{escape(text)}</td></tr>'
        for offset, text, raw in _SEARCH_ROWS
    )
    headers = '<th class="is-sortable is-sort-asc">Offset</th><th class="is-numeric">Len</th><th>Bytes</th><th class="is-wide">ASCII</th>'
    banner = (
        '<div class="hb-banner is-info"><span class="hb-banner-glyph">i</span>'
        '<span class="hb-banner-body"><span class="hb-banner-title">Re-reading matched bytes</span>'
        '<span class="hb-banner-detail">search_* returns offsets only; 4 windows requested</span></span></div>'
    )
    return _section(
        "Search results",
        "The engine returns only <code>(offset, length)</code> pairs and discards the matched bytes. The Bytes and ASCII columns "
        "here were re-read from the document through the window endpoint, which is the only correct way to fill them.",
        _panel("Search", "search_bytes(b'.')", _table(headers, rows), '<span class="hb-mono">4 matches</span>')
        + _frame("While the columns are being re-read", banner),
    )


def _card_patches() -> str:
    """Build the patch list card.

    Returns:
        str: Card body HTML.
    """
    rows = "".join(
        f'<tr><td class="is-mono">0x{offset:08X}</td><td class="is-numeric">{len(new.split())}</td>'
        f'<td class="is-mono hb-dim">{escape(old)}</td><td class="is-wide is-mono is-primary">{escape(new)}</td>'
        f"<td>{_overlap_badge(overlap=overlap)}</td></tr>"
        for offset, old, new, overlap in _PATCH_ROWS
    )
    headers = (
        '<th class="is-sortable is-sort-asc">Offset</th><th class="is-numeric">Len</th>'
        '<th>Original</th><th class="is-wide">New bytes</th><th>Overlap</th>'
    )
    banner = (
        '<div class="hb-banner is-warning"><span class="hb-banner-glyph">!</span>'
        '<span class="hb-banner-body"><span class="hb-banner-title">Document replaced and history cleared</span>'
        '<span class="hb-banner-detail">import_patches_bps rebuilt the buffer, reset the undo stack and cleared file_path(). '
        "Every panel bound to this document must be refreshed.</span></span>"
        '<span class="hb-banner-action"><button type="button" class="hb-btn is-sm">Refresh all</button></span></div>'
    )
    return _section(
        "Patches",
        "<code>get_patches()</code> returns raw, unmerged records that may overlap or repeat. The list shows them exactly as "
        "returned and names the overlaps in words rather than implying them with a tint.",
        _panel("Patches", "get_patches()", _table(headers, rows), '<span class="hb-mono">4 records &middot; 2 overlapping</span>')
        + _frame("After importing a BPS patch set", banner),
    )


def _overlap_badge(*, overlap: bool) -> str:
    """Render the overlap marker for a patch row.

    Args:
        overlap: Whether the record overlaps another.

    Returns:
        str: HTML for the badge.
    """
    if overlap:
        return '<span class="hb-badge is-warning">OVERLAPS</span>'
    return '<span class="hb-badge">clean</span>'


def _card_va_mapping() -> str:
    """Build the virtual address mapping card.

    Returns:
        str: Card body HTML.
    """
    rows = "".join(
        f'<tr><td class="is-mono">0x{offset:08X}</td><td class="is-mono is-primary">0x{address:012X}</td>'
        f'<td class="is-numeric">0x{size:08X}</td><td class="is-mono">{escape(name)}</td>'
        f'<td><span class="hb-badge is-mono">{escape(protection)}</span></td>'
        f'<td class="is-wide"><span class="hb-truncate hb-mono" title="{escape(module)}">{escape(module)}</span></td></tr>'
        for offset, address, size, name, protection, module in _VA_ROWS
    )
    headers = (
        '<th class="is-sortable is-sort-asc">File offset</th><th class="is-sortable">Virtual address</th>'
        '<th class="is-numeric">Size</th><th>Section</th><th>Protection</th><th class="is-wide">Backing module</th>'
    )
    return _section(
        "Virtual address mapping",
        "Mappings added with <code>add_va_mapping</code> drive <code>file_offset_to_va</code> and <code>va_to_file_offset</code>. "
        "Process-memory protections are decoded for reading, with the raw Win32 constant kept alongside them.",
        _panel(
            "Addressing",
            "list_va_mappings()",
            _table(headers, rows),
            '<span class="hb-mono">4 mappings &middot; image base 0x140000000</span>',
        ),
    )


def _card_empty_state() -> str:
    """Build the empty state card.

    Returns:
        str: Card body HTML.
    """
    panels = "".join(
        _panel(
            "Panel",
            "",
            f'<div class="hb-empty"><div class="hb-empty-icon">{icon}</div>'
            f'<div class="hb-empty-title">{escape(title)}</div>'
            f'<div class="hb-empty-hint">{escape(hint)}</div></div>',
            "",
        )
        for icon, title, hint in _EMPTY_STATES
    )
    return _section(
        "Empty states",
        "Every empty state names the reason and the next action. An empty inspector past EOF is a legitimate result, not a "
        "failure, and is worded that way.",
        _grid(panels, "is-wide"),
    )


def _entropy_series() -> tuple[float, ...]:
    """Compute windowed Shannon entropy across the sample buffer.

    Returns:
        tuple[float, ...]: One entropy reading per window of
        ``_ENTROPY_WINDOW`` bytes.
    """
    return tuple(_entropy(_ANALYSIS[start : start + _ENTROPY_WINDOW]) for start in range(0, len(_ANALYSIS), _ENTROPY_WINDOW))


def _entropy_svg() -> str:
    """Render the entropy curve as an inline SVG figure.

    Returns:
        str: SVG markup for the entropy strip.
    """
    series = _entropy_series()
    width = (len(series) - 1) * _STRIP_STEP
    points = " ".join(
        f"{index * _STRIP_STEP:.1f},{_STRIP_HEIGHT - (value / _MAX_ENTROPY) * _STRIP_HEIGHT:.2f}" for index, value in enumerate(series)
    )
    threshold = _STRIP_HEIGHT - (_HIGH_ENTROPY / _MAX_ENTROPY) * _STRIP_HEIGHT
    return (
        f'<svg viewBox="0 0 {width:.0f} {_STRIP_HEIGHT:.0f}" preserveAspectRatio="none" style="width: 100%; height: 96px" '
        'role="img" aria-label="Shannon entropy across the sample buffer">'
        f'<path d="M 0,{_STRIP_HEIGHT:.1f} L {points} L {width:.1f},{_STRIP_HEIGHT:.1f} Z" fill="var(--hb-chart-fill)" '
        'stroke="var(--hb-chart-line)" stroke-width="1" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>'
        f'<line x1="0" y1="{threshold:.2f}" x2="{width:.0f}" y2="{threshold:.2f}" stroke="var(--hb-class-3)" stroke-width="1" '
        'stroke-dasharray="4 3" vector-effect="non-scaling-stroke"/></svg>'
    )


def _card_entropy() -> str:
    """Build the entropy strip analysis card.

    Returns:
        str: Card body HTML.
    """
    series = _entropy_series()
    frame = (
        '<div class="hb-canvasframe"><div class="hb-canvasframe-header">Entropy'
        f'<span class="hb-canvasframe-meta">window {_ENTROPY_WINDOW} B &middot; {len(series)} points &middot; peak {max(series):.2f}</span></div>'
        f'<div class="hb-canvasframe-body">{_entropy_svg()}</div>'
        '<div class="hb-canvasframe-caption">0x00000000 to 0x00003FFF &middot; y axis 0.0 to 8.0 bits per byte</div></div>'
    )
    return _section(
        "Entropy strip",
        f"Shannon entropy over {_ENTROPY_WINDOW} byte windows, {len(series)} readings across the 16 KiB analysis buffer, computed "
        "here rather than asserted. The curve tracks the header, the code section, the string table, a run of alignment padding and "
        "a packed region; the dashed rule marks the 7.0 bit threshold above which the engine calls a block high entropy.",
        frame + '<div class="hb-strip-axis"><span>0x00000000</span><span>0x00002000</span><span>0x00003FFF</span></div>',
    )


def _card_classification() -> str:
    """Build the content classification analysis card.

    Returns:
        str: Card body HTML.
    """
    cells = "".join(
        f'<div class="hb-strip-cell cls-{_classify(_ANALYSIS[start : start + _CLASS_BLOCK])}" '
        f'title="0x{start:08X} class {_classify(_ANALYSIS[start : start + _CLASS_BLOCK])}"></div>'
        for start in range(0, len(_ANALYSIS), _CLASS_BLOCK)
    )
    legend = "".join(
        f'<span class="hb-legend-item"><span class="hb-legend-code">{code}</span>'
        f'<span class="hb-legend-swatch" style="background: var(--hb-class-{code})"></span>'
        f'<span class="hb-legend-label">{escape(name)}</span><span class="hb-legend-note">{note}</span></span>'
        for code, name, note in _CLASS_LEGEND
    )
    start_pct = _PERCENT * _MARKER_START / len(_ANALYSIS)
    width_pct = _PERCENT * _MARKER_LENGTH / len(_ANALYSIS)
    marker = f'<div class="hb-strip-marker" style="--hb-marker-start: {start_pct:.3f}%; --hb-marker-width: {width_pct:.3f}%"></div>'
    return _section(
        "Content classification",
        f"<code>content_classification({_CLASS_BLOCK})</code> returns one code per block, and all five codes occur in this "
        "buffer. Every legend entry carries its numeric code as well as its colour, so the strip stays readable without colour "
        "discrimination and survives greyscale printing.",
        f'<div class="hb-strip"><div class="hb-strip-track is-tall">{cells}</div>'
        '<div class="hb-strip-axis"><span>0x00000000</span><span>block size 256 B</span><span>0x00003FFF</span></div></div>'
        f'<div class="hb-legend">{legend}</div>',
    ) + _section(
        "Selection marker",
        "The strip is the link back to the editor rather than a separate report: whatever is selected in the document is drawn "
        f"over it with <code>hb-strip-marker</code>, so the {_MARKER_LENGTH} bytes under the caret can be located in the whole "
        "buffer at a glance. The marker uses the same selection fill and border as the editor, and never occludes the classes "
        "beneath it.",
        f'<div class="hb-strip"><div class="hb-strip-track is-tall">{cells}{marker}</div>'
        f'<div class="hb-strip-axis"><span>0x00000000</span><span>selection 0x{_MARKER_START:08X} to '
        f"0x{_MARKER_START + _MARKER_LENGTH - 1:08X}</span><span>0x00003FFF</span></div></div>",
    )


def _digram_counts() -> Counter[tuple[int, int]]:
    """Count adjacent byte pairs across the sample buffer.

    Returns:
        Counter[tuple[int, int]]: Occurrence count per ordered byte pair.
    """
    return Counter(pairwise(_ANALYSIS))


def _card_digram() -> str:
    """Build the digram matrix analysis card.

    Returns:
        str: Card body HTML.
    """
    counts = _digram_counts()
    peak = max(counts.values())
    points = "".join(
        f'<rect x="{first}" y="{second}" width="1" height="1" fill="var(--hb-chart-line)" '
        f'fill-opacity="{_MIN_OPACITY + _OPACITY_RANGE * count / peak:.3f}"/>'
        for (first, second), count in counts.items()
    )
    figure = (
        f'<svg class="hb-canvas" viewBox="0 0 {_DIGRAM_SIDE} {_DIGRAM_SIDE}" style="max-width: 380px; aspect-ratio: 1" '
        f'role="img" aria-label="Digram matrix of the sample buffer"><rect width="{_DIGRAM_SIDE}" height="{_DIGRAM_SIDE}" '
        f'fill="var(--hb-surface-inset)"/>{points}</svg>'
    )
    return _section(
        "Digram matrix",
        f"<code>digram_matrix()</code> returns exactly {_DIGRAM_SIDE * _DIGRAM_SIDE} counts, row-major at "
        "<code>idx = b0 * 256 + b1</code>. The dense band is the ASCII string table and the scatter is the packed region. The "
        "frame here is the reusable canvas chrome; the application paints the same figure into a real canvas element at this size.",
        '<div class="hb-canvasframe"><div class="hb-canvasframe-header">Digram'
        f'<span class="hb-canvasframe-meta">{len(counts)} distinct pairs &middot; peak {peak}</span></div>'
        f'<div class="hb-canvasframe-body is-plain">{figure}</div>'
        '<div class="hb-canvasframe-caption">x axis first byte 0x00 to 0xFF &middot; y axis second byte &middot; opacity by count</div></div>',
    )


def _card_histogram() -> str:
    """Build the byte histogram analysis card.

    Returns:
        str: Card body HTML.
    """
    counts = Counter(_ANALYSIS)
    peak = max(counts.values())
    bars = "".join(
        f'<div class="hb-histogram-bar {_byte_class(value)}" style="--hb-bar: {counts.get(value, 0) * _PERCENT / peak:.2f}" '
        f'title="0x{value:02X} occurs {counts.get(value, 0)} times"></div>'
        for value in range(_HISTOGRAM_BINS)
    )
    legend = "".join(
        f'<span class="hb-legend-item"><span class="hb-legend-swatch" style="background: var(--hb-byte-{variable})"></span>'
        f'<span class="hb-legend-label">{escape(label)}</span><span class="hb-legend-note">{escape(note)}</span></span>'
        for variable, (_, label, note, _value) in zip(_BYTE_CLASS_VARS, _BYTE_CLASSES, strict=True)
    )
    return _section(
        "Byte histogram",
        f"All {_HISTOGRAM_BINS} byte values of the analysis buffer, coloured by byte class. The 0x00 bar sets the peak at {peak} "
        "occurrences, which is what padding and alignment produce in a real image.",
        f'<div class="hb-histogram">{bars}</div>'
        '<div class="hb-axis"><span>0x00</span><span>0x40</span><span>0x80</span><span>0xC0</span><span>0xFF</span></div>'
        f'<div class="hb-legend">{legend}</div>',
    )


def _card_segmented_bar() -> str:
    """Build the byte type distribution card.

    Returns:
        str: Card body HTML.
    """
    counts = Counter(_byte_class(value) for value in _ANALYSIS)
    total = len(_ANALYSIS)
    segments = "".join(
        f'<div class="hb-segbar-seg {name}" style="--hb-seg: {counts.get(name, 0) * _PERCENT / total:.3f}" '
        f'title="{escape(label)} {counts.get(name, 0)}">{counts.get(name, 0) * _PERCENT / total:.0f}%</div>'
        for name, label, _note, _value in _BYTE_CLASSES
    )
    rows = "".join(
        f'<tr><td class="is-wide"><span class="hb-swatch" style="background: var(--hb-byte-{variable})"></span> {escape(label)}</td>'
        f'<td class="is-numeric">{counts.get(name, 0)}</td>'
        f'<td class="is-numeric">{counts.get(name, 0) * _PERCENT / total:.1f}%</td>'
        f'<td class="is-mono hb-dim">{escape(note)}</td></tr>'
        for variable, (name, label, note, _value) in zip(_BYTE_CLASS_VARS, _BYTE_CLASSES, strict=True)
    )
    headers = '<th class="is-wide">Class</th><th class="is-numeric">Count</th><th class="is-numeric">Share</th><th>Range</th>'
    return _section(
        "Segmented bar",
        "<code>byte_type_distribution()</code> returns the four counts as a tuple. Each segment wide enough to hold one carries "
        "its percentage inside it, and the table below is the accessible equivalent of the same figure.",
        f'<div class="hb-segbar">{segments}</div>' + _table(headers, rows),
    )


def _card_diff_minimap() -> str:
    """Build the diff mini-map analysis card.

    Returns:
        str: Card body HTML.
    """
    bands = "".join(
        f'<div class="hb-minimap-band {kind}" style="--hb-band-start: {start}; --hb-band-width: {width}" data-glyph="{glyph}"></div>'
        for start, width, kind, glyph in _DIFF_BANDS
    )
    legend = "".join(
        f'<span class="hb-legend-item"><span class="hb-legend-code">{glyph}</span>'
        f'<span class="hb-legend-swatch" style="background: var({colour})"></span>'
        f'<span class="hb-legend-label">{escape(label)}</span></span>'
        for glyph, colour, label in _DIFF_LEGEND
    )
    summary = (
        '<div class="hb-row-flex"><span class="hb-badge is-warning">NOT IDENTICAL</span>'
        '<span class="hb-mono hb-secondary">total_differences = 4</span>'
        '<span class="hb-mono hb-dim">regions = 9</span></div>'
    )
    return _section(
        "Diff mini-map",
        "One band per region from <code>diff_files</code>. Each of the four <code>diff_type</code> values gets a colour and a "
        "glyph, so the map survives greyscale printing and colour blindness. The caret position is tracked by the vertical rule.",
        f'<div class="hb-minimap">{bands}<div class="hb-minimap-cursor" style="--hb-cursor: 31"></div></div>'
        f'<div class="hb-legend">{legend}</div>' + _frame("Summary", summary),
    )


def _argument_control(kind: str) -> str:
    """Render the input control for one parameter kind.

    Args:
        kind: Control kind key from the argument specimen table.

    Returns:
        str: HTML for the control.
    """
    if kind == "select":
        return '<select class="hb-select"><option>utf-8</option><option>utf-16le</option><option>cp1252</option><option>shift_jis</option></select>'
    if kind == "bool":
        return '<label class="hb-check is-checked"><span class="hb-check-box"></span>Match case</label>'
    if kind == "bytes":
        return '<input class="hb-input is-mono" value="4d 5a 90 00" spellcheck="false" aria-label="pattern">'
    if kind == "bytes_block":
        return (
            '<textarea class="hb-textarea is-mono" rows="3" spellcheck="false" aria-label="data">'
            "50 45 00 00 64 86 06 00 6b 1c 5f 65 00 00 00 00\n"
            "00 00 00 00 f0 00 22 00 0b 02 0e 2a 00 6a 01 00</textarea>"
        )
    if kind == "float":
        return '<input class="hb-input is-mono" value="7.0" inputmode="decimal" aria-label="threshold">'
    if kind == "int_pair":
        return (
            '<div class="hb-field-row"><input class="hb-input is-mono is-narrow" value="0x00000100" aria-label="start">'
            '<span class="hb-dim">&rarr;</span>'
            '<input class="hb-input is-mono is-narrow" value="64" aria-label="length"></div>'
        )
    if kind == "bool_pair":
        return (
            '<div class="hb-field-row"><label class="hb-check is-checked"><span class="hb-check-box"></span>forward</label>'
            '<label class="hb-check"><span class="hb-check-box"></span>wrap</label></div>'
        )
    if kind == "bytes_map":
        return _bytes_map_control()
    if kind == "bookmark":
        return _bookmark_control()
    return '<input class="hb-input is-mono" value="0x000000F0" spellcheck="false" aria-label="offset">'


def _bytes_map_control() -> str:
    """Render the editor for a ``dict[str, bytes]`` parameter.

    Returns:
        str: HTML for the map editor.
    """
    return (
        '<div class="hb-map-editor">'
        '<div class="hb-map-row"><input class="hb-input is-mono" value="key" aria-label="parameter name">'
        '<input class="hb-input is-mono" value="0f1e2d3c4b5a69788796a5b4c3d2e1f0" aria-label="parameter value">'
        '<button type="button" class="hb-map-remove" aria-label="Remove">&times;</button></div>'
        '<div class="hb-map-row"><input class="hb-input is-mono" value="padding" aria-label="parameter name">'
        '<input class="hb-input is-mono" value="706b637337" aria-label="parameter value">'
        '<button type="button" class="hb-map-remove" aria-label="Remove">&times;</button></div>'
        '<button type="button" class="hb-map-add">+ add parameter</button></div>'
    )


def _bookmark_control() -> str:
    """Render the editor for a ``Bookmark`` parameter.

    Returns:
        str: HTML for the bookmark editor.
    """
    return (
        '<div class="hb-map-editor">'
        '<div class="hb-map-row"><input class="hb-input is-mono" value="offset" disabled aria-label="field">'
        '<input class="hb-input is-mono" value="0x000000F0" aria-label="offset"><span></span></div>'
        '<div class="hb-map-row"><input class="hb-input is-mono" value="length" disabled aria-label="field">'
        '<input class="hb-input is-mono" value="4" aria-label="length"><span></span></div>'
        '<div class="hb-map-row"><input class="hb-input is-mono" value="label" disabled aria-label="field">'
        '<input class="hb-input" value="PE signature" aria-label="label"><span></span></div>'
        '<div class="hb-map-row"><input class="hb-input is-mono" value="color" disabled aria-label="field">'
        '<input class="hb-input is-mono" value="#4ec98a" aria-label="colour">'
        '<span class="hb-swatch is-lg" style="background: #4ec98a"></span></div></div>'
    )


def _argument_row(name: str, annotation: str, control: str, hint: str) -> str:
    """Render one argument row.

    Args:
        name: Parameter name.
        annotation: Source-level annotation text.
        control: Rendered HTML for the input control.
        hint: Short usage note beneath the control.

    Returns:
        str: HTML for one ``hb-arg``.
    """
    return (
        f'<div class="hb-arg"><span class="hb-arg-label"><span class="hb-arg-name">{escape(name)}</span>'
        f'<span class="hb-arg-type">{escape(annotation)}</span></span>'
        f'<span class="hb-arg-control">{control}<span class="hb-arg-hint">{escape(hint)}</span></span></div>'
    )


def _card_argument_rows() -> str:
    """Build the argument row card covering every value kind.

    Returns:
        str: Card body HTML.
    """
    rows = "".join(
        _argument_row(name, annotation, _argument_control(kind), hint) for _, name, annotation, kind, hint in _ARGUMENT_SPECIMENS
    )
    kinds = "".join(f'<span class="hb-badge is-mono">{escape(label)}</span>' for label, *_rest in _ARGUMENT_SPECIMENS)
    invalid = (
        '<div class="hb-arg is-invalid"><span class="hb-arg-label"><span class="hb-arg-name">pattern</span>'
        '<span class="hb-arg-type">bytes</span></span>'
        '<span class="hb-arg-control"><input class="hb-input is-mono" value="4d 5a x0" spellcheck="false" aria-label="pattern">'
        '<span class="hb-arg-error">expected hexadecimal bytes, got &#39;4d5ax0&#39;</span></span></div>'
    )
    return _section(
        "Argument rows",
        "One control per ValueKind. The label column stacks the parameter name over its exact annotation, so the caller always "
        "sees the type the engine will receive rather than a friendly paraphrase of it.",
        f'<div class="hb-row-flex" style="flex-wrap: wrap">{kinds}</div>'
        + _frame(f"All {len(_ARGUMENT_SPECIMENS)} kinds", f'<div class="hb-stack">{rows}</div>'),
    ) + _section(
        "Invalid argument",
        "A decode failure is reported on the row that caused it, not only in the result panel.",
        _frame("Rejected value", invalid),
    )


def _card_operation_card() -> str:
    """Build the operation card specimen.

    Returns:
        str: Card body HTML.
    """
    arguments = (
        ("name", "str", _TRANSFORM_SELECT, "One of the 23 names from list_transforms()."),
        ("offset", "int", _TRANSFORM_OFFSET, "Start of the run to transform."),
        ("length", "int", _TRANSFORM_LENGTH, "Bytes to cover."),
        ("params", "dict[str, bytes]", _bytes_map_control(), "Every value is raw bytes, entered as hex."),
    )
    body = "".join(starmap(_argument_row, arguments))
    open_card = (
        '<div class="hb-opcard is-open"><div class="hb-opcard-header">'
        '<span class="hb-op-name">transform_data</span>'
        '<span class="hb-op-sig">(name: str, offset: int, length: int, params: dict[str, bytes]) -&gt; None</span>'
        '<span class="hb-badge is-warning">MUTATES</span>'
        '<span class="hb-op-group">Transforms</span></div>'
        f'<div class="hb-opcard-body">{body}</div>'
        '<div class="hb-opcard-footer"><span class="hb-op-hint">Runs against the active document and pushes one undo entry.</span>'
        '<button type="button" class="hb-btn is-ghost">Reset</button>'
        '<button type="button" class="hb-run is-mutating">Run</button></div></div>'
    )
    collapsed = (
        '<div class="hb-opcard"><div class="hb-opcard-header">'
        '<span class="hb-op-name">list_transforms</span>'
        '<span class="hb-op-sig">() -&gt; list[tuple[str, str, str]]</span>'
        '<span class="hb-badge">STATIC</span>'
        '<span class="hb-op-group">Transforms</span></div></div>'
    )
    return _section(
        "Operation card",
        "The header states the exact signature, whether the call mutates the document, and the catalogue group it belongs to. A "
        "static operation needs no document and collapses to its header alone.",
        f'<div class="ds-stack">{open_card}{collapsed}</div>',
    )


def _card_run_states() -> str:
    """Build the run button and button variant card.

    Returns:
        str: Card body HTML.
    """
    runs = "".join(
        f'<div class="ds-item"><button type="button" class="hb-run {name}">{glyph}{escape(label)}</button>'
        f'<div class="ds-caption"><strong>.{escape(name)}</strong> &middot; {escape(note)}</div></div>'
        for name, label, glyph, note in _RUN_STATES
    )
    buttons = "".join(
        f'<div class="ds-item"><button type="button" class="hb-btn {variant}"{" disabled" if off else ""}>{escape(label)}</button>'
        f'<div class="ds-caption">{escape(variant or "default")}</div></div>'
        for variant, label, off in _BUTTON_VARIANTS
    )
    return _section(
        "Run states",
        "The run control keeps its footprint across all five states, so its position never shifts while an operation cycles.",
        _frame("Five states", _grid(runs, "is-narrow")),
    ) + _section(
        "Buttons",
        "Supporting variants used across dialogs, panels and banners.",
        _frame("Variants", _grid(buttons, "is-narrow")),
    )


def _json_key(key: str) -> str:
    """Render a JSON object key.

    Args:
        key: Key text, empty for array elements.

    Returns:
        str: HTML for the key and its separator, empty when there is no key.
    """
    if not key:
        return ""
    style = "hb-json-bytes" if key.startswith("__") else "hb-json-key"
    return f'<span class="{style}">"{escape(key)}"</span><span class="hb-json-punct">:</span>'


def _json_leaf(value: _Json, depth: int, label: str) -> str:
    """Render a scalar JSON value as one row.

    Args:
        value: Scalar value.
        depth: Current nesting depth.
        label: Rendered key markup preceding the value.

    Returns:
        str: HTML for one leaf row.
    """
    if value is None:
        rendered = '<span class="hb-json-null">null</span>'
    elif isinstance(value, bool):
        rendered = f'<span class="hb-json-bool">{"true" if value else "false"}</span>'
    elif isinstance(value, str):
        rendered = f'<span class="hb-json-str">"{escape(value)}"</span>'
    else:
        rendered = f'<span class="hb-json-num">{value}</span>'
    return f'<div class="hb-json-row" style="--hb-json-depth: {depth}"><span class="hb-json-toggle is-leaf"></span>{label}{rendered}</div>'


def _json_container(
    items: list[tuple[str, _Json]],
    depth: int,
    key: str,
    brackets: str,
    collapse: frozenset[str],
) -> list[str]:
    """Render a JSON object or array together with its children.

    Args:
        items: Child key and value pairs; the key is empty for array items.
        depth: Current nesting depth.
        key: Object key introducing this container, empty at the root.
        brackets: The opening and closing bracket characters.
        collapse: Object keys whose containers render closed.

    Returns:
        list[str]: One HTML row per line of the rendered container.
    """
    label = _json_key(key)
    opener, closer = brackets
    open_markup = f'<span class="hb-json-punct">{opener}</span><span class="hb-json-count">{len(items)}</span>'
    if key in collapse:
        folded = (
            f'<div class="hb-json-row" style="--hb-json-depth: {depth}">'
            f'<span class="hb-json-toggle is-collapsed"></span>{label}{open_markup}'
            f'<span class="hb-json-punct">{closer}</span></div>'
        )
        return [folded]
    head = f'<div class="hb-json-row" style="--hb-json-depth: {depth}"><span class="hb-json-toggle"></span>{label}{open_markup}</div>'
    children = [row for child, item in items for row in _json_rows(item, depth + 1, child, collapse)]
    tail = (
        f'<div class="hb-json-row" style="--hb-json-depth: {depth}"><span class="hb-json-toggle is-leaf"></span>'
        f'<span class="hb-json-punct">{closer}</span></div>'
    )
    return [head, *children, tail]


def _json_rows(value: _Json, depth: int, key: str, collapse: frozenset[str] = frozenset()) -> list[str]:
    """Render a JSON value as flat disclosure rows.

    Args:
        value: JSON value to render.
        depth: Current nesting depth, used for indentation.
        key: Object key introducing this value, empty at the root and for
            array elements.
        collapse: Object keys whose containers render closed.

    Returns:
        list[str]: One HTML row per line of the rendered tree.
    """
    if isinstance(value, dict):
        return _json_container(list(value.items()), depth, key, "{}", collapse)
    if isinstance(value, list):
        return _json_container([("", item) for item in value], depth, key, "[]", collapse)
    return [_json_leaf(value, depth, _json_key(key))]


def _card_json_tree() -> str:
    """Build the JSON result tree card.

    Returns:
        str: Card body HTML.
    """
    tree = "".join(_json_rows(_SAMPLE_JSON, 0, ""))
    folded = "".join(_json_rows(_SAMPLE_JSON, 0, "", _COLLAPSED_KEYS))
    hidden = tree.count('class="hb-json-row"') - folded.count('class="hb-json-row"')
    return _section(
        "JSON tree",
        "Results are rendered structurally rather than as a pretty-printed blob. Byte payloads keep their <code>__bytes__</code> "
        "tag and their own colour so a hex string is never mistaken for text, and containers state their child count on the "
        "opening line so a collapsed node still says how much it holds.",
        '<div class="hb-result"><div class="hb-result-header"><span class="hb-result-title">Result</span>'
        '<span class="hb-result-meta"><span>apply_template</span><span>1 root field</span><span>4.1 ms</span></span></div>'
        f'<div class="hb-result-body"><div class="hb-json">{tree}</div></div></div>',
    ) + _section(
        "Collapsed nodes",
        "A closed container keeps its count and closes on the same line, so folding a large array never hides how much was "
        "elided. The disclosure marker turns from &#9662; to &#9656; and stays a real control; only <code>is-leaf</code> rows "
        "hide it entirely.",
        '<div class="hb-result"><div class="hb-result-header"><span class="hb-result-title">Result</span>'
        f'<span class="hb-result-meta"><span>apply_template</span><span>{hidden} rows folded away</span>'
        "<span>4.1 ms</span></span></div>"
        f'<div class="hb-result-body"><div class="hb-json">{folded}</div></div></div>',
    )


def _payload_rows() -> str:
    """Render the leading rows of the sample as a byte payload listing.

    Returns:
        str: HTML for the payload rows.
    """
    return "".join(
        f'<div class="hb-payload-row"><span class="hb-payload-off">{start:08X}</span>'
        f'<span class="hb-payload-hex">{" ".join(f"{value:02x}" for value in _SAMPLE[start : start + _ROW_WIDTH])}</span>'
        f'<span class="hb-payload-ascii">{"".join(_ascii_glyph(value) for value in _SAMPLE[start : start + _ROW_WIDTH])}</span></div>'
        for start in range(0, _PAYLOAD_ROWS * _ROW_WIDTH, _ROW_WIDTH)
    )


def _card_payload() -> str:
    """Build the byte payload and truncation card.

    Returns:
        str: Card body HTML.
    """
    return _section(
        "Byte payload",
        "Any result tagged <code>__bytes__</code> is offered as a hex dump with an ASCII gutter, addressed from the offset the "
        "call was made at rather than from zero.",
        '<div class="hb-result"><div class="hb-result-header"><span class="hb-result-title">read_bytes(0, 4096)</span>'
        '<span class="hb-result-meta"><span>4096 B</span><span>truncated</span></span></div>'
        f'<div class="hb-result-body"><div class="hb-payload">{_payload_rows()}</div></div></div>',
    ) + _section(
        "Truncation banner",
        "The transport caps inline payloads at 4096 bytes but always reports the true length, so the banner can state exactly how "
        "much was elided and offer the window endpoint instead of silently showing less.",
        '<div class="hb-banner is-truncated"><span class="hb-banner-glyph">&#8942;</span>'
        '<span class="hb-banner-body"><span class="hb-banner-title">Showing 4096 of 1462272 bytes</span>'
        '<span class="hb-banner-detail">encode_result capped the inline payload; 1458176 bytes were elided</span></span>'
        '<span class="hb-banner-action"><button type="button" class="hb-btn is-sm">Open in editor</button></span></div>',
    )


def _card_result_panel() -> str:
    """Build the result panel and banner card.

    Returns:
        str: Card body HTML.
    """
    rows = "".join(
        f'<div class="hb-json-row"><span class="hb-json-toggle is-leaf"></span>'
        f'<span class="hb-json-key">{escape(name)}</span><span class="hb-json-punct">&rarr;</span>'
        f'<span class="{style}">{escape(value)}</span></div>'
        for name, value, style in _SCALAR_RESULTS
    )
    banners = "".join(
        f'<div class="hb-banner is-{kind}"><span class="hb-banner-glyph">{glyph}</span>'
        f'<span class="hb-banner-body"><span class="hb-banner-title">{escape(title)}</span>'
        f'<span class="hb-banner-detail">{escape(detail)}</span></span></div>'
        for kind, glyph, title, detail in _RESULT_BANNERS
    )
    return _section(
        "Result panel",
        "The header repeats what was run and how long it took. Scalar returns are shown inline rather than wrapped in a single-node tree.",
        '<div class="hb-result"><div class="hb-result-header"><span class="hb-result-title">Result</span>'
        '<span class="hb-result-meta"><span>4 calls</span><span>0.8 ms</span></span></div>'
        f'<div class="hb-result-body"><div class="hb-json">{rows}</div></div></div>',
    ) + _section(
        "Banners",
        "Notices that belong to the result as a whole rather than to a single argument.",
        f'<div class="ds-stack">{banners}</div>',
    )


def _card_errors() -> str:
    """Build the error banner, toast and dialog card.

    Returns:
        str: Card body HTML.
    """
    banners = "".join(
        f'<div class="hb-error-banner err-{kind}"><span class="hb-error-kind">{escape(label)}</span>'
        f'<span class="hb-error-message">{escape(message)}</span>'
        f'<span class="hb-error-detail">{escape(detail)}</span></div>'
        for kind, label, message, detail in _ERROR_KINDS
    )
    toasts = "".join(
        f'<div class="hb-toast is-{kind}"><span class="hb-toast-glyph">{glyph}</span>'
        f'<span class="hb-toast-body"><span class="hb-toast-title">{escape(title)}</span>'
        f'<span class="hb-toast-detail">{escape(detail)}</span></span>'
        '<button type="button" class="hb-toast-close" aria-label="Dismiss">&times;</button></div>'
        for kind, glyph, title, detail in _TOAST_SPECIMENS
    )
    return (
        _section(
            "Error kinds",
            "Every exception the engine can raise has its own banner. The kind is spelled out in a monospace tag as well as "
            "coloured, and the second line names the call that raised it so the message is actionable on its own.",
            f'<div class="ds-stack">{banners}</div>',
        )
        + _section("Toasts", "Transient outcomes that belong to no open panel.", f'<div class="hb-toast-stack is-embedded">{toasts}</div>')
        + _section("Dialog", "Modal confirmation for an irreversible action.", _dialog())
    )


def _dialog() -> str:
    """Render the modal confirmation dialog specimen.

    Returns:
        str: HTML for the dialog on its overlay stage.
    """
    return (
        '<div class="ds-overlaystage"><div class="hb-scrim"></div>'
        '<div class="hb-dialog"><div class="hb-dialog-header"><span class="hb-dialog-title">Import BPS patch set</span>'
        '<button type="button" class="hb-dialog-close" aria-label="Close">&times;</button></div>'
        '<div class="hb-dialog-body"><p>Importing a BPS patch set replaces the entire document, resets the undo stack and clears '
        "the recorded file path. This cannot be undone.</p>"
        '<div class="hb-banner is-warning"><span class="hb-banner-glyph">!</span>'
        '<span class="hb-banner-body"><span class="hb-banner-title">4 unsaved edits will be discarded</span>'
        '<span class="hb-banner-detail">kernel32.dll has pending modifications at 0x148 and 0x14C</span></span></div></div>'
        '<div class="hb-dialog-footer"><button type="button" class="hb-btn">Cancel</button>'
        '<button type="button" class="hb-btn is-danger">Replace document</button></div></div></div>'
    )


def _css() -> str:
    """Read the canonical stylesheet.

    Returns:
        str: Full contents of ``static/app.css``.
    """
    return _CSS_PATH.read_text(encoding="utf-8")


def _render(card: _Card, stylesheet: str) -> str:
    """Assemble one complete standalone card document.

    Args:
        card: Card to render.
        stylesheet: Contents of the canonical stylesheet, inlined verbatim.

    Returns:
        str: Full HTML document whose first line is the ``@dsCard`` marker.
    """
    return "\n".join((
        f'<!-- @dsCard group="{card.group}" -->',
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>hexbench &middot; {escape(card.title)}</title>",
        "<style>",
        stylesheet,
        _CHROME_CSS,
        "</style>",
        "</head>",
        '<body class="ds-body">',
        '<header class="ds-head">',
        f'<div class="ds-eyebrow">{escape(card.group)}</div>',
        f'<h1 class="ds-title">{escape(card.title)}</h1>',
        "</header>",
        f'<main class="ds-main">{card.body}</main>',
        "</body>",
        "</html>",
        "",
    ))


def _all_cards() -> tuple[_Card, ...]:
    """Assemble every card in the gallery.

    Returns:
        tuple[_Card, ...]: Cards in the order they are written.
    """
    return (
        _Card("foundations-colour.html", "Foundations", "Colour tokens", _card_colour_tokens()),
        _Card("foundations-type.html", "Foundations", "Type scale", _card_type_scale()),
        _Card("foundations-spacing.html", "Foundations", "Spacing and radius", _card_spacing()),
        _Card("foundations-elevation.html", "Foundations", "Elevation", _card_elevation()),
        _Card("foundations-monospace.html", "Foundations", "Monospace stack", _card_mono_specimen()),
        _Card("editor-byte-states.html", "Editor", "Byte cell states", _card_byte_states()),
        _Card("editor-row-and-ruler.html", "Editor", "Row, gutter and ruler", _card_row_and_ruler()),
        _Card("editor-sample-view.html", "Editor", "Sample view", _card_sample_view()),
        _Card("editor-busy.html", "Editor", "Busy hatch", _card_busy()),
        _Card("chrome-app-shell.html", "Chrome", "Application shell", _card_app_shell()),
        _Card("chrome-menubar.html", "Chrome", "Menu bar", _card_menubar()),
        _Card("chrome-toolbar.html", "Chrome", "Toolbar", _card_toolbar()),
        _Card("chrome-document-tabs.html", "Chrome", "Document tabs", _card_document_tabs()),
        _Card("chrome-dock-tabs.html", "Chrome", "Dock tabs and splitters", _card_dock_tabs()),
        _Card("chrome-statusbar.html", "Chrome", "Status bar", _card_statusbar()),
        _Card("chrome-command-palette.html", "Chrome", "Command palette", _card_palette()),
        _Card("panels-frame.html", "Panels", "Panel frame and table", _card_panel_frame()),
        _Card("panels-inspector.html", "Panels", "Inspector", _card_inspector()),
        _Card("panels-template-tree.html", "Panels", "Template tree", _card_template_tree()),
        _Card("panels-strings.html", "Panels", "Strings", _card_strings()),
        _Card("panels-search-results.html", "Panels", "Search results", _card_search_results()),
        _Card("panels-patches.html", "Panels", "Patches", _card_patches()),
        _Card("panels-va-mapping.html", "Panels", "Virtual address mapping", _card_va_mapping()),
        _Card("panels-empty-state.html", "Panels", "Empty states", _card_empty_state()),
        _Card("analysis-entropy.html", "Analysis", "Entropy strip", _card_entropy()),
        _Card("analysis-classification.html", "Analysis", "Content classification", _card_classification()),
        _Card("analysis-digram.html", "Analysis", "Digram matrix", _card_digram()),
        _Card("analysis-histogram.html", "Analysis", "Byte histogram", _card_histogram()),
        _Card("analysis-segmented-bar.html", "Analysis", "Byte type distribution", _card_segmented_bar()),
        _Card("analysis-diff-minimap.html", "Analysis", "Diff mini-map", _card_diff_minimap()),
        _Card("operations-card.html", "Operations", "Operation card", _card_operation_card()),
        _Card("operations-arguments.html", "Operations", "Argument rows", _card_argument_rows()),
        _Card("operations-run-states.html", "Operations", "Run states and buttons", _card_run_states()),
        _Card("operations-result.html", "Operations", "Result panel", _card_result_panel()),
        _Card("operations-json-tree.html", "Operations", "JSON tree", _card_json_tree()),
        _Card("operations-payload.html", "Operations", "Byte payload", _card_payload()),
        _Card("operations-errors.html", "Operations", "Errors, toasts and dialog", _card_errors()),
    )


def build_cards() -> tuple[str, ...]:
    """Write every preview card into the cards directory.

    Existing files are overwritten, so repeated runs converge on byte-identical
    output. Propagates :class:`OSError` when the stylesheet cannot be read or
    the cards directory cannot be written.

    Returns:
        tuple[str, ...]: File names written, in gallery order.
    """
    _CARDS_DIR.mkdir(parents=True, exist_ok=True)
    stylesheet = _css()
    cards = _all_cards()
    for card in cards:
        (_CARDS_DIR / card.filename).write_text(_render(card, stylesheet), encoding="utf-8", newline="\r\n")
    return tuple(card.filename for card in cards)


def main() -> int:
    """Generate the cards and report what was written.

    Returns:
        int: Process exit status, zero on success.
    """
    written = build_cards()
    sys.stdout.write(f"{len(written)} cards written to {_CARDS_DIR}\n")
    sys.stdout.writelines(f"  {name}\n" for name in written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
