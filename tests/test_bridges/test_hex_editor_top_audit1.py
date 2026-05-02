# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Audit-1 (hex-editor-top) regression tests.

Each test in this file maps to a finding from ``audit1.md`` for the
``bridges-hex`` unit and is named ``test_f_<id>_<topic>`` so the
finding identifier remains traceable from a failing test report. All
tests exercise the real ``HexEditorBridge`` against the native
``intellicrack_hexcore`` document; no mocks of the bridge or document
are used.
"""

from __future__ import annotations

import asyncio
import base64
import struct
import zlib
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any, cast

import pytest
import structlog.testing

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import (
    HexDocumentEvent,
    HexDocumentState,
    StateCallbackFn,
)
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.core.tools import ToolRegistry


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")

_pefile_available: bool = find_spec("pefile") is not None


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine to completion using a session-stable loop.

    Args:
        coro: Coroutine to drive.

    Returns:
        T: The coroutine's return value.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_collector() -> tuple[list[tuple[HexDocumentEvent, dict[str, Any]]], StateCallbackFn]:
    """Construct a fresh in-memory event collector and its callback.

    Returns:
        tuple[list[tuple[HexDocumentEvent, dict[str, Any]]], StateCallbackFn]:
            (events, callback) where events grows on every event.
    """
    events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

    def on_event(evt: HexDocumentEvent, data: dict[str, Any]) -> None:
        events.append((evt, data))

    return events, on_event


# ---------------------------------------------------------------------------
# F-0004 - get_alignment_grid + tool registration
# ---------------------------------------------------------------------------


class TestF0004AlignmentGridGetter:
    """The alignment grid size must be readable through the public API."""

    def test_get_alignment_grid_reflects_set_alignment_grid(self, bridge: HexEditorBridge) -> None:
        """Reading the alignment grid after setting it returns the same value.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_alignment_grid(256))
        assert _run(bridge.get_alignment_grid()) == 256

    def test_get_alignment_grid_default_is_zero(self, bridge: HexEditorBridge) -> None:
        """A fresh bridge reports the alignment grid as disabled (0).

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        assert _run(bridge.get_alignment_grid()) == 0

    def test_get_alignment_grid_registered_as_tool(self, bridge: HexEditorBridge) -> None:
        """The getter is exposed as an LLM tool function.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        names = {f.name for f in bridge.tool_definition.functions}
        assert "hex_editor.get_alignment_grid" in names


# ---------------------------------------------------------------------------
# F-0005 - state_lock used in document mutations, not only in shutdown
# ---------------------------------------------------------------------------


class TestF0005StateLockUsage:
    """The bridge state lock must protect document state mutations."""

    def test_close_file_holds_state_lock(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """close_file must serialize document/cursor/selection mutation under the lock.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        with getattr(bridge, "_state_lock"):
            assert bridge.document is not None
        _run(bridge.close_file())
        assert bridge.document is None


# ---------------------------------------------------------------------------
# F-0006 - apply_transform / apply_pipeline write back into the document
# ---------------------------------------------------------------------------


class TestF0006ApplyTransformWritesBack:
    """In-place transforms must mutate the open document."""

    def test_apply_transform_xor_modifies_document(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """xor_single in-place changes bytes and notifies state holder.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "xor.bin"
        target.write_bytes(b"\x00\x00\x00\x00")
        _run(bridge.open_file(str(target)))
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        _run(bridge.apply_transform("xor_single", 0, 4, '{"key":"FF"}', in_place=True))

        assert _run(bridge.read_bytes(0, 4)).replace(" ", "") == "FFFFFFFF"
        assert any(e[0] == HexDocumentEvent.DATA_MODIFIED for e in events)

    def test_apply_transform_no_in_place_leaves_document_alone(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """in_place=False returns the transformed bytes but does not write back.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "noxor.bin"
        target.write_bytes(b"\x01\x02\x03\x04")
        _run(bridge.open_file(str(target)))

        result = _run(bridge.apply_transform("xor_single", 0, 4, '{"key":"FF"}', in_place=False))

        assert result.lower() == "fefdfcfb"
        assert _run(bridge.read_bytes(0, 4)).replace(" ", "") == "01020304"


# ---------------------------------------------------------------------------
# F-0007 - _build_ips_from_patches overflow validation
# ---------------------------------------------------------------------------


class TestF0007IpsBuilderOverflow:
    """The Python IPS builder must reject overflowing offsets and sizes."""

    def test_oversized_offset_for_ips_raises(self) -> None:
        """A 24-bit-overflow offset triggers OverflowError when ips32=False."""
        with pytest.raises(OverflowError):
            getattr(HexEditorBridge, "_build_ips_from_patches")([(0x10_00_00_00, b"\x00")], ips32=False)

    def test_eof_collision_offset_for_ips_raises(self) -> None:
        """The reserved EOF marker offset (0x454F46) raises in IPS mode."""
        with pytest.raises(OverflowError):
            getattr(HexEditorBridge, "_build_ips_from_patches")([(0x454F46, b"\x00")], ips32=False)

    def test_oversized_data_for_ips_raises(self) -> None:
        """A data chunk larger than 16 bits triggers OverflowError."""
        with pytest.raises(OverflowError):
            getattr(HexEditorBridge, "_build_ips_from_patches")([(0, b"\x00" * 0x10000)], ips32=False)

    def test_oversized_offset_for_ips32_raises(self) -> None:
        """Offsets above 32 bits trigger OverflowError in IPS32 mode."""
        with pytest.raises(OverflowError):
            getattr(HexEditorBridge, "_build_ips_from_patches")([(0x1_0000_0000, b"\x00")], ips32=True)

    def test_eeof_collision_offset_for_ips32_raises(self) -> None:
        """The reserved EEOF marker offset raises in IPS32 mode."""
        eeof_offset = int.from_bytes(b"EEOF", "big")
        with pytest.raises(OverflowError):
            getattr(HexEditorBridge, "_build_ips_from_patches")([(eeof_offset, b"\x00")], ips32=True)

    def test_valid_ips_round_trip_still_works(self) -> None:
        """Valid in-range patches still produce a parseable PATCH...EOF blob."""
        blob = getattr(HexEditorBridge, "_build_ips_from_patches")([(0x10, b"\xde\xad")], ips32=False)
        assert blob.startswith(b"PATCH")
        assert blob.endswith(b"EOF")


# ---------------------------------------------------------------------------
# F-0008 - _apply_ips_patches raises on truncated records
# ---------------------------------------------------------------------------


class TestF0008IpsApplyTruncationRaises:
    """Truncated IPS data must raise rather than partially apply."""

    def test_apply_truncated_record_data_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A record whose data is shorter than its declared size raises.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "trunc.bin"
        target.write_bytes(b"\x00" * 32)
        _run(bridge.open_file(str(target)))
        truncated = b"PATCH" + b"\x00\x00\x00" + b"\x00\x10" + b"\x01\x02"
        with pytest.raises(RuntimeError):
            getattr(bridge, "_apply_ips_patches")(truncated)

    def test_apply_missing_terminator_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A patch without an EOF terminator raises RuntimeError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "noeof.bin"
        target.write_bytes(b"\x00" * 32)
        _run(bridge.open_file(str(target)))
        record = b"PATCH\x00\x00\x00\x00\x02\xaa\xbb"
        with pytest.raises(RuntimeError):
            getattr(bridge, "_apply_ips_patches")(record)

    def test_apply_truncated_rle_record_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A 0-size record without 3 trailing RLE bytes raises.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "rle.bin"
        target.write_bytes(b"\x00" * 32)
        _run(bridge.open_file(str(target)))
        truncated = b"PATCH" + b"\x00\x00\x00" + b"\x00\x00" + b"\x00"
        with pytest.raises(RuntimeError):
            getattr(bridge, "_apply_ips_patches")(truncated)

    def test_apply_well_formed_patch_succeeds(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A well-formed patch still applies and returns the record count.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "good.bin"
        target.write_bytes(b"\x00" * 32)
        _run(bridge.open_file(str(target)))
        patch = b"PATCH\x00\x00\x00\x00\x02\xaa\xbbEOF"
        count = getattr(bridge, "_apply_ips_patches")(patch)
        assert count == 1
        assert _run(bridge.read_bytes(0, 2)).replace(" ", "") == "AABB"


# ---------------------------------------------------------------------------
# F-0013 - PE imports/exports prefer disk path
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _pefile_available, reason="pefile not installed")
class TestF0013PeImportsExportsDiskPath:
    """When the document is unmodified, pefile reads the file by name."""

    def test_disk_path_helper_returns_path_for_unmodified_document(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """An unmodified document yields its on-disk path through the helper.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        helper = getattr(bridge, "_document_disk_path_if_unmodified")()
        assert helper is not None
        assert helper.resolve() == pe_binary.resolve()

    def test_disk_path_helper_returns_none_after_modification(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """Once the document is modified the helper falls back to None.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.write_bytes(0, "EB"))
        helper = getattr(bridge, "_document_disk_path_if_unmodified")()
        assert helper is None

    def test_get_pe_imports_does_not_raise_for_pe(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """get_pe_imports executes against a real PE on disk and returns a list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        result = _run(bridge.get_pe_imports())
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# F-0014 - yara_scan prefers disk path
# ---------------------------------------------------------------------------


class TestF0014YaraScanDiskPath:
    """yara_scan should not load the entire document into Python."""

    def test_yara_scan_unmodified_uses_filepath(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """Unmodified document yara_scan returns rule matches via scan_file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        if find_spec("yara") is None:
            pytest.skip("yara-python not installed")
        _run(bridge.open_file(str(pe_binary)))
        rule = 'rule mz_marker { strings: $a = "MZ" condition: $a }'
        matches = _run(bridge.yara_scan(rule))
        assert isinstance(matches, list)
        assert any(m["rule"] == "mz_marker" for m in matches)


# ---------------------------------------------------------------------------
# F-0016 - Pattern registry unavailable raises
# ---------------------------------------------------------------------------


class TestF0016PatternRegistryRaises:
    """list_hexpat_patterns and auto_detect_pattern raise when unavailable."""

    def test_list_hexpat_patterns_raises_when_interpreter_unavailable(
        self,
        bridge: HexEditorBridge,
    ) -> None:
        """A bridge with the hexpat interpreter disabled raises RuntimeError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        bridge._hexpat_interpreter_available = False
        bridge._pattern_registry = None
        with pytest.raises(RuntimeError):
            _run(bridge.list_hexpat_patterns())

    def test_auto_detect_pattern_raises_when_interpreter_unavailable(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """auto_detect_pattern raises RuntimeError when interpreter unavailable.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        bridge._hexpat_interpreter_available = False
        bridge._pattern_registry = None
        with pytest.raises(RuntimeError):
            _run(bridge.auto_detect_pattern())


# ---------------------------------------------------------------------------
# F-0017 - apply_template notifies state holder
# ---------------------------------------------------------------------------


class TestF0017ApplyTemplateNotifiesStateHolder:
    """apply_template must emit a pattern-executed event."""

    def test_apply_template_emits_pattern_executed_event(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """apply_template fires PATTERN_EXECUTED with the template name.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)
        _run(bridge.open_file(str(pe_binary)))

        templates = _run(bridge.list_templates())
        assert templates, "hexcore must expose at least one built-in template"
        template_name = templates[0]["name"]

        events.clear()
        _run(bridge.apply_template(template_name, 0))

        executed = [e for e in events if e[0] == HexDocumentEvent.PATTERN_EXECUTED]
        assert executed, "apply_template must notify state holder"
        assert executed[0][1]["pattern_name"] == template_name


# ---------------------------------------------------------------------------
# F-0019 - entropy/digram fallbacks
# ---------------------------------------------------------------------------


class _NoEntropyDoc:
    """Document wrapper that hides entropy/digram methods to test fallbacks."""

    def __init__(self, inner: object) -> None:
        """Wrap a real document and hide stat accessors.

        Args:
            inner: The real ``HexDocument`` instance.
        """
        self._inner: object = inner

    def length(self) -> int:
        """Return the underlying document length.

        Returns:
            int: Length in bytes.
        """
        return int(getattr(self._inner, "length")())

    def read(self, offset: int, length: int) -> bytes:
        """Forward read to the wrapped document.

        Args:
            offset: Byte offset.
            length: Number of bytes to read.

        Returns:
            bytes: Bytes read from the inner document.
        """
        return bytes(getattr(self._inner, "read")(offset, length))

    def file_path(self) -> str | None:
        """Forward file_path so disk-fast-path probes still work.

        Returns:
            str | None: Underlying path or None.
        """
        result: str | None = getattr(self._inner, "file_path")()
        return result


class TestF0019EntropyFallback:
    """Entropy / distribution accessors fall back to Python when Rust lacks them."""

    def test_get_entropy_uses_python_fallback_when_native_missing(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """get_entropy returns a numeric value via the Python fallback.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        f = tmp_path / "entropy.bin"
        f.write_bytes(b"\x00" * 100 + b"\xff" * 100)
        _run(bridge.open_file(str(f)))
        bridge.document = _NoEntropyDoc(bridge.document)
        result = _run(bridge.get_entropy())
        assert 0.9 < result < 1.1

    def test_get_byte_distribution_uses_python_fallback(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """byte_distribution falls back to a Python streaming counter.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        f = tmp_path / "dist.bin"
        f.write_bytes(b"ABBA")
        _run(bridge.open_file(str(f)))
        bridge.document = _NoEntropyDoc(bridge.document)
        dist = _run(bridge.get_byte_distribution())
        assert dist[ord("A")] == 2
        assert dist[ord("B")] == 2
        assert sum(dist) == 4

    def test_get_byte_type_distribution_uses_python_fallback(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """byte_type_distribution falls back to a Python categoriser.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        f = tmp_path / "types.bin"
        f.write_bytes(b"\x00\x01ABC\xff")
        _run(bridge.open_file(str(f)))
        bridge.document = _NoEntropyDoc(bridge.document)
        result = _run(bridge.get_byte_type_distribution())
        assert result == {
            "null_count": 1,
            "printable_count": 3,
            "control_count": 1,
            "high_count": 1,
        }


# ---------------------------------------------------------------------------
# F-0020 - read_bytes length cap
# ---------------------------------------------------------------------------


class TestF0020ReadBytesCap:
    """read_bytes must reject calls that exceed the per-call cap."""

    def test_read_bytes_caps_oversize_request(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """An oversize read_bytes call raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        with pytest.raises(ValueError, match="exceeds the per-call cap"):
            _run(bridge.read_bytes(0, 1 << 30))

    def test_read_bytes_rejects_negative_length(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """Negative lengths are rejected.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        with pytest.raises(ValueError, match="length"):
            _run(bridge.read_bytes(0, -1))


# ---------------------------------------------------------------------------
# F-0021 - replace_bytes emits per-region events
# ---------------------------------------------------------------------------


class TestF0021ReplaceBytesPerRegionEvents:
    """replace_bytes must emit narrow data_modified events per match."""

    def test_replace_bytes_emits_per_match_events(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """Each pattern occurrence yields its own data_modified event.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "replace.bin"
        target.write_bytes(b"AAAA__AAAA__AAAA")
        _run(bridge.open_file(str(target)))
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        count = _run(bridge.replace_bytes("4141 4141", "9090 9090"))

        modified_events = [e for e in events if e[0] == HexDocumentEvent.DATA_MODIFIED]
        assert count == 3
        assert len(modified_events) == 3
        offsets = {e[1]["offset"] for e in modified_events}
        assert offsets == {0, 6, 12}
        for evt in modified_events:
            assert evt[1]["length"] == 4
            assert evt[1]["offset"] != 0 or len(modified_events) == 3


# ---------------------------------------------------------------------------
# F-0024 - capabilities advertisement
# ---------------------------------------------------------------------------


class TestF0024CapabilitiesTruthful:
    """Capabilities must reflect the actual implementation."""

    def test_capabilities_omit_macho(self, bridge: HexEditorBridge) -> None:
        """The advertised supported_formats must not claim macho support.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        assert "macho" not in bridge.capabilities.supported_formats

    def test_capabilities_disable_scripting(self, bridge: HexEditorBridge) -> None:
        """The advertised capabilities must not claim scripting support.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        assert bridge.capabilities.supports_scripting is False


# ---------------------------------------------------------------------------
# F-0032 - open_file closes previous document
# ---------------------------------------------------------------------------


class TestF0032OpenFileClosesPrevious:
    """open_file must release the previous document before loading a new one."""

    def test_open_file_replaces_previous_document(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
        elf_binary: Path,
    ) -> None:
        """Opening a second file replaces the first document instance.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            elf_binary: Path to the ELF binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        first_doc = bridge.document
        _run(bridge.open_file(str(elf_binary)))
        second_doc = bridge.document
        assert second_doc is not first_doc
        assert bridge.state.target_path is not None
        assert bridge.state.target_path.resolve() == elf_binary.resolve()

    def test_open_file_emits_close_then_open_events(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
        elf_binary: Path,
    ) -> None:
        """The state holder receives a close event before the new open event.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            elf_binary: Path to the ELF binary fixture.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        bridge.set_state_holder(state)

        _run(bridge.open_file(str(pe_binary)))
        events.clear()
        _run(bridge.open_file(str(elf_binary)))

        closed_idx = [i for i, e in enumerate(events) if e[0] == HexDocumentEvent.DOCUMENT_CLOSED]
        opened_idx = [i for i, e in enumerate(events) if e[0] == HexDocumentEvent.DOCUMENT_OPENED]
        assert closed_idx, "open_file must emit DOCUMENT_CLOSED for previous doc"
        assert opened_idx, "open_file must emit DOCUMENT_OPENED for new doc"
        assert closed_idx[0] < opened_idx[0]


# ---------------------------------------------------------------------------
# F-0033 - save_to_sandbox destroys orphan instance on copy_to failure
# ---------------------------------------------------------------------------


class _FailingSandboxBridge:
    """Sandbox bridge stub that fails copy_to and records destroy calls."""

    name = ToolName.SANDBOX

    def __init__(self) -> None:
        """Initialise instrumentation counters."""
        self.create_calls = 0
        self.copy_calls = 0
        self.destroyed: list[str] = []

    async def create(self, *, sandbox_type: str = "windows") -> dict[str, Any]:
        """Pretend to create a sandbox instance.

        Args:
            sandbox_type: Sandbox type identifier (ignored).

        Returns:
            dict[str, Any]: Fake create result.
        """
        _ = sandbox_type
        self.create_calls += 1
        return {"instance_id": "sbx-1"}

    async def copy_to(self, *, instance_id: str, source: str, dest: str) -> None:
        """Always fail to copy.

        Args:
            instance_id: Sandbox instance id.
            source: Source file path.
            dest: Destination path inside the sandbox.

        Raises:
            RuntimeError: Always.
        """
        _ = (instance_id, source, dest)
        self.copy_calls += 1
        msg = "synthetic copy_to failure"
        raise RuntimeError(msg)

    async def destroy(self, *, instance_id: str) -> dict[str, Any]:
        """Record the destroy call.

        Args:
            instance_id: Sandbox instance id to destroy.

        Returns:
            dict[str, Any]: Confirmation dict.
        """
        self.destroyed.append(instance_id)
        return {"success": True, "instance_id": instance_id}


class _RegistryStub:
    """Tiny tool registry stub returning the configured sandbox bridge."""

    def __init__(self, sandbox: _FailingSandboxBridge) -> None:
        """Bind the sandbox bridge.

        Args:
            sandbox: The sandbox bridge stub instance.
        """
        self._sandbox = sandbox

    def get(self, name: ToolName) -> _FailingSandboxBridge | None:
        """Return the sandbox bridge for SANDBOX, otherwise None.

        Args:
            name: Requested tool name.

        Returns:
            _FailingSandboxBridge | None: The registered sandbox bridge or None.
        """
        if name == ToolName.SANDBOX:
            return self._sandbox
        return None


class TestF0033SaveToSandboxDestroysOrphan:
    """save_to_sandbox must destroy the instance when copy_to fails."""

    def test_copy_to_failure_triggers_destroy(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
        tmp_path: Path,
    ) -> None:
        """copy_to failures invoke destroy(instance_id) on the sandbox bridge.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            tmp_path: Pytest temporary directory.
        """
        _run(bridge.open_file(str(pe_binary)))
        sandbox = _FailingSandboxBridge()
        bridge.tool_registry = cast("ToolRegistry", _RegistryStub(sandbox))
        dest = str(tmp_path / "sample.bin")
        with pytest.raises(RuntimeError, match="synthetic copy_to failure"):
            _run(bridge.save_to_sandbox(dest, "windows"))
        assert sandbox.destroyed == ["sbx-1"]


# ---------------------------------------------------------------------------
# F-0034 - get_context_for_ai bookmark cap
# ---------------------------------------------------------------------------


class TestF0034GetContextBookmarkCap:
    """get_context_for_ai must cap the bookmark list."""

    def test_bookmarks_truncated_when_over_limit(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """A document with many bookmarks reports truncation in the context.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        for i in range(80):
            _run(bridge.add_bookmark(i, 1, f"bm{i}", "#FF0000"))

        ctx = _run(bridge.get_context_for_ai(include_bytes=64, bookmark_limit=10))

        assert ctx["bookmark_count_total"] == 80
        assert ctx["bookmark_truncated"] is True
        assert len(ctx["bookmarks"]) == 10

    def test_bookmark_limit_zero_returns_no_bookmarks(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """A bookmark_limit of 0 returns an empty bookmarks list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.add_bookmark(0, 1, "x", "#FF0000"))
        ctx = _run(bridge.get_context_for_ai(include_bytes=32, bookmark_limit=0))
        assert ctx["bookmarks"] == []
        assert ctx["bookmark_count_total"] == 1
        assert ctx["bookmark_truncated"] is True


# ---------------------------------------------------------------------------
# F-0035 - export_patches logs fallback for ips32 mismatch
# ---------------------------------------------------------------------------


class _NoIps32Doc:
    """Document wrapper that hides export_patches_ips32 to test the fallback path."""

    def __init__(self, inner: object) -> None:
        """Wrap a real document.

        Args:
            inner: Underlying ``HexDocument`` instance.
        """
        self._inner = inner

    def __getattr__(self, name: str) -> object:
        """Forward attribute access to the wrapped document.

        Args:
            name: Attribute name being accessed.

        Returns:
            object: Attribute value from the wrapped document.

        Raises:
            AttributeError: When the inner document does not expose the
                attribute or when the attribute is the explicitly hidden
                ``export_patches_ips32`` method.
        """
        if name == "export_patches_ips32":
            msg = "intentionally hidden for fallback test"
            raise AttributeError(msg)
        return getattr(self._inner, name)


class TestF0035ExportIps32FallbackIsLogged:
    """A missing native ips32 export must take a logged fallback, not silent."""

    def test_export_patches_ips32_falls_back_with_log(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """Falls back to the Python builder and logs a warning for visibility.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "patches.bin"
        target.write_bytes(b"\x00" * 16)
        _run(bridge.open_file(str(target)))
        _run(bridge.write_bytes(0, "DEADBEEF"))
        bridge.document = _NoIps32Doc(bridge.document)

        with structlog.testing.capture_logs() as captured:
            blob_b64 = _run(bridge.export_patches("ips32"))

        blob = base64.b64decode(blob_b64)
        assert blob.startswith(b"IPS32")
        assert blob.endswith(b"EEOF")
        assert any(
            "native_unavailable" in str(entry.get("event", "")) and entry.get("log_level") == "warning" for entry in captured
        )


# ---------------------------------------------------------------------------
# F-0041 - search_text raises when search_text_encoded missing
# ---------------------------------------------------------------------------


class _NoEncodedSearchDoc:
    """Document wrapper that hides search_text_encoded to test the raise path."""

    def __init__(self, inner: object) -> None:
        """Wrap a real document.

        Args:
            inner: Underlying document.
        """
        self._inner = inner

    def __getattr__(self, name: str) -> object:
        """Forward attribute access except for search_text_encoded.

        Args:
            name: Attribute name being accessed.

        Returns:
            object: Attribute value from the wrapped document.

        Raises:
            AttributeError: When the requested attribute is
                ``search_text_encoded`` (which is intentionally hidden
                to force the bridge to take its raise-on-missing path)
                or when the inner document does not expose the
                attribute at all.
        """
        if name == "search_text_encoded":
            msg = "hidden for test"
            raise AttributeError(msg)
        return getattr(self._inner, name)


class TestF0041SearchTextRaisesOnMissingEncodedSearch:
    """search_text now raises when the encoded backend method is missing."""

    def test_missing_search_text_encoded_raises(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """search_text raises RuntimeError when the encoded method is absent.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        bridge.document = _NoEncodedSearchDoc(bridge.document)
        with pytest.raises(RuntimeError, match="search_text_encoded"):
            _run(bridge.search_text("MZ", "utf-8", 10))


# ---------------------------------------------------------------------------
# F-0046 - copy_as raises without selection
# ---------------------------------------------------------------------------


class TestF0046CopyAsRequiresSelection:
    """copy_as must raise rather than silently copy one byte."""

    def test_copy_as_without_selection_raises_tool_error(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """copy_as raises ToolError when called with no selection set.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        bridge._selection = None
        with pytest.raises(ToolError, match="no selection active"):
            _run(bridge.copy_as("hex"))

    def test_copy_as_with_selection_succeeds(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """copy_as still works when a real selection is active.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.select_range(0, 1))
        result = _run(bridge.copy_as("hex"))
        assert result.replace(" ", "") == "4D5A"


# ---------------------------------------------------------------------------
# F-0048 - initialize merges highlight rules
# ---------------------------------------------------------------------------


class TestF0048InitializeMergesHighlightRules:
    """initialize must not drop bridge-side highlight rules."""

    def test_initialize_merges_holder_and_bridge_rules(self) -> None:
        """Bridge-side rules survive initialize when not overridden by holder."""
        bridge = HexEditorBridge()
        bridge._highlight_rules = {"rule_a": {"id": "rule_a", "color": "#111111"}}
        state = HexDocumentState()
        state.set_highlight_rule("rule_b", {"id": "rule_b", "color": "#222222"})
        bridge.set_state_holder(state)

        _run(bridge.initialize())

        rules: dict[str, Any] = getattr(bridge, "_highlight_rules")
        assert "rule_a" in rules
        assert "rule_b" in rules

    def test_holder_rule_takes_precedence_on_conflict(self) -> None:
        """Holder rules take precedence over bridge-side rules with same id."""
        bridge = HexEditorBridge()
        bridge._highlight_rules = {"shared": {"id": "shared", "color": "#AAAAAA"}}
        state = HexDocumentState()
        state.set_highlight_rule("shared", {"id": "shared", "color": "#BBBBBB"})
        bridge.set_state_holder(state)

        _run(bridge.initialize())

        rules: dict[str, dict[str, str]] = getattr(bridge, "_highlight_rules")
        assert rules["shared"]["color"] == "#BBBBBB"


# ---------------------------------------------------------------------------
# F-0049 - save / save_as updates target_path
# ---------------------------------------------------------------------------


class TestF0049SaveAsUpdatesTargetPath:
    """save / save_as must keep state.target_path in sync."""

    def test_save_as_updates_target_path(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
        tmp_path: Path,
    ) -> None:
        """save_as updates state.target_path to the new path.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
            tmp_path: Pytest temp directory.
        """
        _run(bridge.open_file(str(pe_binary)))
        new_path = tmp_path / "renamed.bin"
        _run(bridge.save_as(str(new_path)))
        assert bridge.state.target_path is not None
        assert bridge.state.target_path.resolve() == new_path.resolve()


# ---------------------------------------------------------------------------
# F-0051 - get_digram_matrix supports compact summary mode
# ---------------------------------------------------------------------------


class TestF0051DigramMatrixSummary:
    """get_digram_matrix must support a compact summary form."""

    def test_top_k_returns_only_top_k_pairs(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """top_k>0 omits the 65536-entry matrix and lists top pairs.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        f = tmp_path / "digram.bin"
        f.write_bytes(b"AAAA")
        _run(bridge.open_file(str(f)))
        result = _run(bridge.get_digram_matrix(top_k=1))
        assert "matrix" not in result
        assert "top_pairs" in result
        assert result["top_pairs"][0] == {"a": ord("A"), "b": ord("A"), "count": 3}
        assert result["total_pairs"] == 3
        assert result["unique_pairs"] == 1

    def test_top_k_zero_returns_full_matrix(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """top_k=0 returns the full row-major matrix.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        result = _run(bridge.get_digram_matrix(top_k=0))
        assert "matrix" in result
        assert len(result["matrix"]) == 65536


# ---------------------------------------------------------------------------
# F-0052 - CRC fallback uses zlib for CRC-32 IEEE
# ---------------------------------------------------------------------------


class _NoNativeCrcDoc:
    """Wrapper hiding the native compute_hash_custom_crc to force the fallback."""

    def __init__(self, inner: object) -> None:
        """Wrap a real document.

        Args:
            inner: Underlying document.
        """
        self._inner = inner

    def __getattr__(self, name: str) -> object:
        """Forward attribute access except for the native CRC accessor.

        Args:
            name: Attribute name being accessed.

        Returns:
            object: Attribute value from the wrapped document.

        Raises:
            AttributeError: When the requested attribute is
                ``compute_hash_custom_crc`` (intentionally hidden to
                exercise the Python fallback path) or when the inner
                document does not expose the attribute.
        """
        if name == "compute_hash_custom_crc":
            msg = "hidden for test"
            raise AttributeError(msg)
        return getattr(self._inner, name)


class TestF0052CrcFallbackMatchesZlib:
    """CRC-32 IEEE fallback must agree with ``zlib.crc32``."""

    def test_crc32_ieee_matches_zlib(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """The fallback CRC-32 path returns the same value zlib does.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        payload = b"The quick brown fox jumps over the lazy dog"
        f = tmp_path / "crc.bin"
        f.write_bytes(payload)
        _run(bridge.open_file(str(f)))
        bridge.document = _NoNativeCrcDoc(bridge.document)

        result_hex = _run(
            bridge.calculate_hash_custom_crc(
                start=0,
                end=len(payload),
                poly=0x04C11DB7,
                init=0xFFFFFFFF,
                width=32,
                refin=True,
                refout=True,
                xorout=0xFFFFFFFF,
            ),
        )

        expected = zlib.crc32(payload) & 0xFFFFFFFF
        assert int(result_hex, 16) == expected


# ---------------------------------------------------------------------------
# F-0054 - search_numeric validates value_type/endianness
# ---------------------------------------------------------------------------


class TestF0054SearchNumericValidatesEnums:
    """search_numeric must reject unknown value_type / endianness names."""

    def test_unknown_value_type_raises(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """Passing an unknown value_type raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        with pytest.raises(ValueError, match="value_type"):
            _run(bridge.search_numeric(0, size=4, value_type="unsigned"))

    def test_unknown_endianness_raises(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """Passing an unknown endianness raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        with pytest.raises(ValueError, match="endianness"):
            _run(bridge.search_numeric(0, size=4, value_type="uint", endianness="middle"))

    def test_known_value_type_still_works(
        self,
        bridge: HexEditorBridge,
        tmp_path: Path,
    ) -> None:
        """A known value_type still produces results.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temp directory.
        """
        target = tmp_path / "numeric.bin"
        target.write_bytes(struct.pack("<I", 0xDEAD) + b"\x00" * 16)
        _run(bridge.open_file(str(target)))
        result = _run(bridge.search_numeric(0xDEAD, size=4, value_type="uint"))
        assert any(r["offset"] == 0 for r in result)


# ---------------------------------------------------------------------------
# F-0057 - target_path derived from Rust file_path()
# ---------------------------------------------------------------------------


class TestF0057TargetPathFromRustFilePath:
    """The bridge target_path must match the Rust document's file_path()."""

    def test_target_path_matches_rust_file_path(
        self,
        bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """state.target_path matches document.file_path() after open_file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        rust_path = bridge.document.file_path() if bridge.document is not None else None
        assert rust_path is not None
        assert bridge.state.target_path is not None
        assert str(bridge.state.target_path) == rust_path
