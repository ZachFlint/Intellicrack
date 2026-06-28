# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave 5 native-helper gates: private functions and Windows-native operations.

Findings closed:
    3   get_memory_regions — MemoryRegion fields on self-process
    23  analyze_entropy — Shannon entropy oracle against ctypes-controlled buffers
    24  yara_scan — pre-process guards and live pattern-match via ctypes buffer
    25  adjust_privilege — invalid-name deterministic error path
    26  get_resources — ntdll.dll resource directory structure via pefile oracle
    28  _coerce_address — exact int/bool/str/None dispatch
    29  _x64dbg_error_code — exact str/absent/non-str dispatch
"""

from __future__ import annotations

import ctypes
import math
import os
import sys
from pathlib import Path
from typing import Any, Final, cast

import pefile
import pytest

import intellicrack.bridges.x64dbg as _x64dbg_module
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import MemoryRegion, ToolError


_coerce_address: Any = vars(_x64dbg_module)["_coerce_address"]
_x64dbg_error_code: Any = vars(_x64dbg_module)["_x64dbg_error_code"]

_NTDLL_PATH: Final[Path] = Path(r"C:\Windows\System32\ntdll.dll")
_BOGUS_PRIV: Final[str] = "SeBogusInvalidPrivilegeWave5"

_YARA_RULE: Final[str] = (
    "rule IntellicrockTestPattern {\n    strings:\n        $a = { 49 4E 54 45 4C 4C 49 43 52 41 43 4B }\n    condition:\n        $a\n}"
)
_YARA_PATTERN: Final[bytes] = b"INTELLICRACK"


def _attach_self(bridge: X64DbgBridge) -> None:
    """Attach ``bridge`` to the current process for Windows-native tests.

    Calling this instead of installing a fake pipe is correct for the
    native-API tests (``get_memory_regions``, ``read_memory``, …) which
    bypass the pipe entirely.

    Args:
        bridge: Bridge instance to configure.
    """
    setattr(bridge, "_attached_pid", os.getpid())


class TestCoerceAddress:
    """Unit tests for the private ``_coerce_address`` helper.

    The function is accessed via ``vars(module)["_coerce_address"]`` to
    avoid triggering ``reportPrivateUsage`` under strict basedpyright.
    """

    def test_bool_true_returns_none(self) -> None:
        """``True`` is a ``bool`` subclass; bools are explicitly rejected.

        Oracle: x64dbg.py:408 ``if isinstance(value, bool): return None``.
        Mutation caught: removing the bool guard and falling through to the
        int branch → returns 1 instead of None → assertion fails.
        """
        bool_true: bool = True
        assert _coerce_address(bool_true) is None

    def test_bool_false_returns_none(self) -> None:
        """``False`` is also rejected, not converted to 0.

        Oracle: x64dbg.py:408 ``if isinstance(value, bool): return None``.
        Mutation caught: removing the bool check → returns 0 → assertion fails.
        """
        bool_false: bool = False
        assert _coerce_address(bool_false) is None

    def test_plain_int_passthrough(self) -> None:
        """A plain ``int`` (non-bool) is returned unchanged.

        Oracle: x64dbg.py:410 ``if isinstance(value, int): return value``.
        Mutation caught: returning ``None`` unconditionally for all ints →
        assertion fails.
        """
        assert _coerce_address(0xDEAD) == 0xDEAD

    def test_zero_int_passthrough(self) -> None:
        """0 (a valid address) is returned as 0, not confused with None/False.

        Oracle: x64dbg.py:410 ``if isinstance(value, int): return value``.
        Mutation caught: treating 0 as falsy and returning None → fails.
        """
        assert _coerce_address(0) == 0

    def test_hex_string_parsed_to_int(self) -> None:
        """A hex string (e.g. ``"0xDEAD"``) is parsed via ``safe_int_from_str``.

        Oracle: x64dbg.py:414 ``return safe_int_from_str(candidate, base=0, ...)``;
        ``int("0xDEAD", 0)`` == 57005 (verified manually).
        Mutation caught: using ``base=10`` → parse fails → returns None.
        """
        assert _coerce_address("0xDEAD") == 57005

    def test_decimal_string_parsed_to_int(self) -> None:
        """A decimal string (``"255"``) is also parseable with ``base=0``.

        Oracle: ``int("255", 0)`` == 255.
        Mutation caught: rejecting digit-only strings → returns None.
        """
        assert _coerce_address("255") == 255

    def test_unparseable_string_returns_none(self) -> None:
        """A string that is not a valid integer (e.g. ``"not_hex"``) → ``None``.

        Oracle: x64dbg.py:414 ``safe_int_from_str`` returns ``None`` on failure.
        Mutation caught: returning 0 for invalid strings → assertion fails.
        """
        assert _coerce_address("not_hex") is None

    def test_empty_string_returns_none(self) -> None:
        """An empty (or whitespace-only) string → ``None`` without error.

        Oracle: x64dbg.py:413 ``if candidate := value.strip(): ... return None``.
        Mutation caught: removing the strip/empty guard → parse attempt on
        empty string raises ValueError or returns wrong value.
        """
        assert _coerce_address("") is None

    def test_none_returns_none(self) -> None:
        """``None`` is not an int or str; falls through to the final return.

        Oracle: x64dbg.py:416 ``return None`` (fallthrough for non-bool,
        non-int, non-str values).
        Mutation caught: treating None as 0 → assertion fails.
        """
        assert _coerce_address(None) is None

    def test_float_returns_none(self) -> None:
        """A ``float`` is not accepted; not a bool, int, or str.

        Oracle: x64dbg.py:416 final ``return None``.
        Mutation caught: adding a ``isinstance(value, float)`` branch that
        converts floats → returns an int → assertion fails.
        """
        assert _coerce_address(math.pi) is None


class TestX64dbgErrorCode:
    """Unit tests for the private ``_x64dbg_error_code`` helper.

    The function is accessed via ``vars(module)["_x64dbg_error_code"]`` to
    avoid triggering ``reportPrivateUsage`` under strict basedpyright.
    """

    def test_string_code_in_details_is_returned(self) -> None:
        """A ``str`` value for ``x64dbg_error_code`` in ``exc.details`` is returned.

        Oracle: x64dbg.py:388 ``return raw_code if isinstance(raw_code, str) else None``.
        Mutation caught: returning ``raw_code`` unconditionally (no isinstance
        guard) → when raw_code is an int, wrong type returned; this direction
        is green but the non-str case below catches the flip.
        """
        exc = ToolError("test error", details={"x64dbg_error_code": "pipe_disconnected"})
        assert _x64dbg_error_code(exc) == "pipe_disconnected"

    def test_absent_key_returns_none(self) -> None:
        """``ToolError`` with no ``x64dbg_error_code`` key → ``None``.

        Oracle: x64dbg.py:388 ``exc.details.get("x64dbg_error_code")`` returns
        ``None`` when the key is absent; ``isinstance(None, str)`` is ``False``.
        Mutation caught: raising ``KeyError`` instead of returning ``None``
        (i.e., using ``exc.details["x64dbg_error_code"]``) → assertion fails.
        """
        exc = ToolError("no detail")
        assert _x64dbg_error_code(exc) is None

    def test_non_string_code_returns_none(self) -> None:
        """An integer ``x64dbg_error_code`` (protocol error) → ``None``.

        Oracle: x64dbg.py:388 ``isinstance(raw_code, str)`` is ``False`` for
        integers → function returns ``None``.
        Mutation caught: removing the isinstance guard → integer is returned
        instead of None → assertion fails.
        """
        exc = ToolError("test error", details={"x64dbg_error_code": 42})
        assert _x64dbg_error_code(exc) is None

    def test_different_string_code_is_returned_verbatim(self) -> None:
        """A second distinct error code string is returned unchanged.

        Oracle: same as ``test_string_code_in_details_is_returned`` but with a
        different value to confirm no hardcoded string comparison.
        Mutation caught: hardcoding ``"pipe_disconnected"`` as the return value →
        ``"remote_error"`` mismatch → assertion fails.
        """
        exc = ToolError("remote err", details={"x64dbg_error_code": "remote_error"})
        assert _x64dbg_error_code(exc) == "remote_error"


@pytest.mark.skipif(sys.platform != "win32", reason="VirtualQueryEx requires Windows")
@pytest.mark.asyncio
class TestGetMemoryRegions:
    """Gate ``get_memory_regions`` — MemoryRegion fields on the self-process."""

    async def test_self_process_regions_have_nonzero_base_and_size(self) -> None:
        """Regions from the running Python process have ``base_address > 0`` and ``size > 0``.

        Oracle: Windows process address space — the first committed page in any
        process is above VA 0; every committed region has non-zero size.
        Mutation caught: zeroing ``base_address`` or ``size`` in
        ``_append_committed_region`` → assertion fails.
        """
        bridge = X64DbgBridge()
        _attach_self(bridge)
        regions: list[MemoryRegion] = await bridge.get_memory_regions()

        assert any(r.base_address > 0 for r in regions), "Expected at least one region with base_address > 0"
        assert any(r.size > 0 for r in regions), "Expected at least one region with size > 0"

    async def test_self_process_has_at_least_one_readable_region(self) -> None:
        """The running Python process has at least one region with ``'r'`` in protection.

        Oracle: Every process has readable code and data segments; ``read``
        protection maps to ``'r'`` in the bridge's string encoding.
        Mutation caught: replacing all ``'r'`` chars with ``'-'`` in the
        protection string logic → no readable region found → assertion fails.
        """
        bridge = X64DbgBridge()
        _attach_self(bridge)
        regions: list[MemoryRegion] = await bridge.get_memory_regions()

        assert any("r" in r.protection for r in regions), "Expected at least one region with 'r' in protection"

    async def test_region_objects_are_memoryregion_instances(self) -> None:
        """Each returned object is a ``MemoryRegion`` with all expected fields.

        Oracle: x64dbg.py:_append_committed_region builds ``MemoryRegion``
        dataclass instances with named fields.
        Mutation caught: returning raw dicts instead of dataclass instances →
        attribute access fails → assertion fails.
        """
        bridge = X64DbgBridge()
        _attach_self(bridge)
        regions: list[MemoryRegion] = await bridge.get_memory_regions()

        assert len(regions) > 0
        r0 = regions[0]
        assert isinstance(r0, MemoryRegion)
        assert hasattr(r0, "base_address")
        assert hasattr(r0, "size")
        assert hasattr(r0, "protection")
        assert len(r0.protection) == 3, f"Expected 3-char protection string, got {r0.protection!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="ReadProcessMemory requires Windows")
@pytest.mark.asyncio
class TestAnalyzeEntropy:
    """Gate ``analyze_entropy`` — Shannon entropy oracle against known buffers.

    Uses ``ctypes`` to allocate in-process buffers with controlled content so
    ``ReadProcessMemory`` returns exactly the bytes expected by the oracle.
    """

    async def test_all_zero_block_has_entropy_zero(self) -> None:
        """A 256-byte all-zero block has Shannon entropy 0.0.

        Oracle: Shannon entropy formula — when all bytes are identical (one
        symbol), H = -(1.0 * log2(1.0)) = 0.0.  ``round(0.0, 4) == 0.0``.
        Mutation caught: computing entropy without normalising by block length →
        wrong probability → non-zero entropy returned → assertion fails.
        """
        buf = (ctypes.c_uint8 * 256)()
        addr = ctypes.addressof(buf)

        bridge = X64DbgBridge()
        _attach_self(bridge)

        results: list[dict[str, Any]] = await bridge.analyze_entropy(addr, 256, block_size=256)

        assert len(results) == 1
        block = results[0]
        assert block["readable"] is True
        assert block["size"] == 256
        assert block["entropy"] == pytest.approx(0.0)

    async def test_alternating_bytes_block_has_entropy_one(self) -> None:
        """A block with exactly 128 zeros and 128 0xFF bytes has entropy 1.0.

        Oracle: With two equiprobable symbols (p=0.5 each), Shannon entropy
        H = -(0.5*log2(0.5) + 0.5*log2(0.5)) = 1.0 bits.
        ``round(1.0, 4) == 1.0``.
        Mutation caught: using ``log`` instead of ``log2`` → entropy = 1/ln(2)
        ≈ 1.4427 → assertion fails.
        """
        buf = (ctypes.c_uint8 * 256)(*[0xFF if i % 2 == 1 else 0x00 for i in range(256)])
        addr = ctypes.addressof(buf)

        bridge = X64DbgBridge()
        _attach_self(bridge)

        results: list[dict[str, Any]] = await bridge.analyze_entropy(addr, 256, block_size=256)

        assert len(results) == 1
        block = results[0]
        assert block["readable"] is True
        expected_entropy: float = round(-2 * (0.5 * math.log2(0.5)), 4)
        assert block["entropy"] == expected_entropy

    async def test_address_field_is_hex_string_of_start_address(self) -> None:
        """The ``address`` field in each result is ``hex(block_start_address)``.

        Oracle: x64dbg.py:7882 ``"address": hex(current_addr)``.
        Mutation caught: using ``str(current_addr)`` (decimal) → hex format
        mismatch → assertion fails.
        """
        buf = (ctypes.c_uint8 * 256)()
        addr = ctypes.addressof(buf)

        bridge = X64DbgBridge()
        _attach_self(bridge)

        results: list[dict[str, Any]] = await bridge.analyze_entropy(addr, 256, block_size=256)

        assert len(results) == 1
        assert results[0]["address"] == hex(addr)

    async def test_unreadable_block_has_readable_false_and_error_field(self) -> None:
        """A block at an invalid address reports ``readable=False`` with an ``error``.

        Oracle: x64dbg.py:7855-7861 — a ``ToolError`` from ``read_memory``
        yields ``{"readable": False, "error": str(exc), "entropy": 0.0}``.
        Mutation caught: silently dropping the read error → ``readable`` key
        becomes ``True`` or ``error`` key is absent → assertion fails.
        """
        bridge = X64DbgBridge()
        _attach_self(bridge)

        bad_addr = 0x1

        results: list[dict[str, Any]] = await bridge.analyze_entropy(bad_addr, 256, block_size=256)

        assert len(results) == 1
        block = results[0]
        assert block["readable"] is False
        assert "error" in block


@pytest.mark.asyncio
class TestYaraScan:
    """Gate ``yara_scan`` — pre-process guards and live scan via ctypes buffer."""

    async def test_no_rule_raises_tool_error(self) -> None:
        """``yara_scan()`` with neither ``rule_text`` nor ``rule_path`` raises.

        Oracle: x64dbg.py:7928-7929 ``if not rule_text and not rule_path: raise
        ToolError(_ERR_YARA_NO_RULE, ...)``.
        Mutation caught: removing this guard → function proceeds to compile
        ``None`` as a YARA rule → raises a different exception type (not
        ``ToolError``) or succeeds → pytest.raises context does not match →
        test fails.
        """
        bridge = X64DbgBridge()
        with pytest.raises(ToolError, match=r"requires rule_text or rule_path"):
            await bridge.yara_scan()

    async def test_empty_rule_text_raises_tool_error(self) -> None:
        """An empty ``rule_text`` string raises ``ToolError`` via the no-rule guard.

        ``not ""`` is truthy, so ``rule_text=""`` without a ``rule_path`` hits
        the first guard at x64dbg.py:7928-7929 (``_ERR_YARA_NO_RULE``) before
        the length check at 7931-7932 can fire.

        Oracle: x64dbg.py:7928-7929 ``if not rule_text and not rule_path: raise
        ToolError(_ERR_YARA_NO_RULE)``.
        Mutation caught: removing this guard → ``rule_text=""`` proceeds past
        both checks and fails inside yara-python rather than raising
        ``ToolError`` with the expected message → match fails.
        """
        bridge = X64DbgBridge()
        with pytest.raises(ToolError, match=r"requires rule_text or rule_path"):
            await bridge.yara_scan(rule_text="")

    @pytest.mark.skipif(sys.platform != "win32", reason="ReadProcessMemory requires Windows")
    async def test_live_scan_finds_known_pattern_in_ctypes_buffer(self) -> None:
        """A YARA rule matching a known pattern finds it in a controlled ctypes buffer.

        RED_BY_DESIGN — PD-007.

        A 256-byte buffer is allocated with ``INTELLICRACK`` bytes at offset 0.
        The YARA rule targets exactly those 12 bytes (hex pattern).  The bridge
        reads the buffer via ``ReadProcessMemory`` (self-process) and runs YARA
        on the result.  The match dict is checked for exact rule name and
        matched byte content.

        This test is intentionally red until PD-007 is fixed.  Production
        ``x64dbg.py:7977`` unpacks ``m.strings`` as
        ``for offset_val, _identifier, match_bytes in strings_list`` but modern
        yara-python returns ``yara.StringMatch`` objects (not 3-tuples), raising
        ``TypeError: cannot unpack non-iterable yara.StringMatch object`` inside
        ``_scan_window`` before any result is appended.

        Oracle: YARA spec — the rule hex pattern ``49 4E 54 45 4C 4C 49 43 52
        41 43 4B`` matches ASCII ``INTELLICRACK``; ``matched_bytes`` is the
        hex encoding of those bytes (``b"INTELLICRACK".hex()``).
        Mutation caught: computing ``matched_bytes`` as
        ``match_bytes.decode("latin-1")`` instead of ``.hex()`` → value differs
        → assertion fails.
        """
        buf_size = 256
        buf_data = _YARA_PATTERN + b"\x00" * (buf_size - len(_YARA_PATTERN))
        buf = (ctypes.c_uint8 * buf_size)(*buf_data)
        addr = ctypes.addressof(buf)

        bridge = X64DbgBridge()
        _attach_self(bridge)

        results: list[dict[str, Any]] = await bridge.yara_scan(
            rule_text=_YARA_RULE,
            address=addr,
            size=buf_size,
        )

        assert len(results) == 1
        match = results[0]
        assert match["rule"] == "IntellicrockTestPattern"
        assert match["matched_bytes"] == _YARA_PATTERN.hex()


@pytest.mark.skipif(sys.platform != "win32", reason="LookupPrivilegeValueW requires Windows")
@pytest.mark.asyncio
class TestAdjustPrivilege:
    """Gate ``adjust_privilege`` — deterministic error path for invalid names."""

    async def test_invalid_privilege_name_returns_success_false_with_not_found_message(self) -> None:
        """An unknown privilege name returns ``success=False`` with exact error text.

        Oracle: x64dbg.py:9094-9096 ``if not advapi32.LookupPrivilegeValueW(None,
        name, ctypes.byref(luid)): return {"success": False,
        "error": f"Privilege {name!r} not found"}``.
        Mutation caught: returning ``{"success": True}`` → first assertion fails;
        or changing the f-string to omit the name → error string mismatch →
        second assertion fails.
        """
        result: dict[str, Any] = await X64DbgBridge.adjust_privilege(_BOGUS_PRIV)

        assert result["success"] is False
        assert result.get("error") == f"Privilege {_BOGUS_PRIV!r} not found"


@pytest.mark.skipif(sys.platform != "win32", reason="Toolhelp and ReadProcessMemory require Windows")
@pytest.mark.skipif(not _NTDLL_PATH.exists(), reason="ntdll.dll not present at expected system path")
@pytest.mark.asyncio
class TestGetResources:
    """Gate ``get_resources`` — PE resource directory structure via pefile oracle."""

    async def test_ntdll_has_version_resource_matching_pefile(self) -> None:
        """``get_resources("ntdll.dll")`` includes an ``RT_VERSION`` entry.

        ntdll.dll on all supported Windows versions contains a version-info
        resource (``type_id == 16``, ``type_name == "RT_VERSION"``).  pefile
        independently confirms this from the on-disk binary.

        Oracle: ``pefile.PE(ntdll_path)`` shows an entry with resource type id
        16 in ``DIRECTORY_ENTRY_RESOURCE.entries``.
        Mutation caught: returning ``type_name = f"RT_{type_id}"`` for ALL types
        (including the well-known ones) → ``"RT_VERSION"`` is the fallback, not
        the named value → assertion on ``type_name`` still passes; changing type
        detection to yield ``type_id == 0`` for version info → assertion fails.
        """
        pe = pefile.PE(str(_NTDLL_PATH))
        pe.parse_data_directories()
        pefile_type_ids: set[int] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            dir_res: Any = getattr(pe, "DIRECTORY_ENTRY_RESOURCE")
            for entry in cast("list[Any]", getattr(dir_res, "entries", [])):
                entry_id: Any = getattr(entry, "id", None)
                if entry_id is not None:
                    pefile_type_ids.add(int(entry_id))
        pe.close()

        bridge = X64DbgBridge()
        _attach_self(bridge)

        resources: list[dict[str, Any]] = await bridge.get_resources("ntdll.dll")

        assert len(resources) > 0, "ntdll.dll should expose at least one resource entry"

        bridge_type_ids: set[int] = {int(r["type_id"]) for r in resources if r.get("type_id") is not None}
        shared_ids: set[int] = pefile_type_ids & bridge_type_ids
        assert len(shared_ids) > 0, f"No overlap between pefile type_ids {pefile_type_ids} and bridge type_ids {bridge_type_ids}"

        version_resources = [r for r in resources if r.get("type_id") == 16]
        assert len(version_resources) > 0, (
            "ntdll.dll must expose an RT_VERSION resource (type_id == 16); "
            f"bridge reported type_ids: {[r.get('type_id') for r in resources]}"
        )
        assert 16 in pefile_type_ids, "pefile oracle must also report type_id 16 (RT_VERSION) in ntdll.dll"
        rv = version_resources[0]
        assert rv["type_id"] == 16
        assert isinstance(rv["type_name"], str)
        assert rv["type_name"]
        assert isinstance(rv["size"], int)
        assert rv["size"] > 0

    async def test_each_resource_entry_has_required_fields(self) -> None:
        """Every entry has ``type_id``, ``type_name``, ``id``, ``language``, ``rva``, ``size``.

        Oracle: x64dbg.py:8804-8814 the dict assembled per leaf has all of
        these fields explicitly set.
        Mutation caught: omitting ``rva`` from the assembled dict → assertion
        on required-field presence fails.
        """
        bridge = X64DbgBridge()
        _attach_self(bridge)

        resources: list[dict[str, Any]] = await bridge.get_resources("ntdll.dll")

        required_fields = {"type_id", "type_name", "id", "language", "rva", "size"}
        for resource in resources:
            missing = required_fields - resource.keys()
            assert not missing, f"Resource entry missing fields: {missing}"
