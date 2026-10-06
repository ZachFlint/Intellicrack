# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Critical-coverage tests for the second slice of ``intellicrack.bridges.hex_editor``.

The slice spans the integer and float parsing helpers, the DIE and ClamAV signature
matchers, the BPS and UPS patch encoders and decoders, the file, sandbox and byte-editing
mixins, and the state-holder notifications they emit. Every expectation is derived
independently of the product code: the BPS and UPS wire formats are assembled byte by byte
from the format definitions with ``struct`` and ``zlib``, MD5 digests come from ``hashlib``,
float views from ``struct``, and byte transforms are worked out by hand. Sandbox bridges
are subclasses of the real ``HexEditorBridge`` registered on a real ``ToolRegistry``.
"""

from __future__ import annotations

import contextlib
import gc
import hashlib
import re
import shutil
import struct
import tempfile
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import intellicrack_hexcore
import pytest
from structlog.testing import capture_logs

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence

    from intellicrack.core.types import HexDocumentFull


type _Event = tuple[HexDocumentEvent, dict[str, Any]]

_OBSERVER_ID = "critcov-observer"
_BRIDGE_SOURCE = "bridge"


class _EventLog:
    """Observer collecting every event a ``HexDocumentState`` delivers to it."""

    def __init__(self) -> None:
        """Start with an empty event list."""
        self.events: list[_Event] = []

    def __call__(self, event: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Record one delivered event.

        Args:
            event: Event type delivered by the state holder.
            data: Payload delivered with the event.
        """
        self.events.append((event, data))


class _FailingCopySandbox(HexEditorBridge):
    """Sandbox bridge that provisions an instance and then refuses every copy."""

    def create(self, *, sandbox_type: str) -> dict[str, Any]:
        """Return a provisioned-instance record naming the requested sandbox type.

        Args:
            sandbox_type: Sandbox flavor requested by the bridge under test.

        Returns:
            dict[str, Any]: Instance record whose identifier embeds ``sandbox_type``.
        """
        return {"instance_id": f"{sandbox_type}-orphan-3", "type": sandbox_type, "status": "running"}

    def copy_to(self, *, instance_id: str, source: str, dest: str) -> dict[str, Any]:
        """Refuse to copy.

        Args:
            instance_id: Identifier previously returned by ``create``.
            source: Host-side file that would be copied.
            dest: Intended destination path.

        Returns:
            dict[str, Any]: Never returned.

        Raises:
            RuntimeError: Always.
        """
        msg = f"copy refused for {instance_id}: {source} -> {dest}"
        raise RuntimeError(msg)


class _DestroyingSandbox(_FailingCopySandbox):
    """Failing-copy sandbox bridge that also exposes a synchronous ``destroy`` hook."""

    def __init__(self, *, fail_destroy: bool = False) -> None:
        """Start with no destroyed instances.

        Args:
            fail_destroy: Whether ``destroy`` raises after recording the instance.
        """
        super().__init__()
        self.destroyed: list[str] = []
        self.fail_destroy = fail_destroy

    def destroy(self, *, instance_id: str) -> dict[str, Any]:
        """Record the instance as destroyed, optionally failing afterwards.

        Args:
            instance_id: Identifier of the instance to destroy.

        Returns:
            dict[str, Any]: Destruction record.

        Raises:
            RuntimeError: When ``fail_destroy`` was requested.
        """
        self.destroyed.append(instance_id)
        if self.fail_destroy:
            msg = f"destroy refused for {instance_id}"
            raise RuntimeError(msg)
        return {"instance_id": instance_id, "status": "destroyed"}


class _HostActionSandbox(HexEditorBridge):
    """Sandbox bridge whose ``copy_to`` also manipulates the host bridge's document or source file."""

    def __init__(self, host: HexEditorBridge, *, copy_action: Literal["drop_host_document", "consume_source"]) -> None:
        """Remember the host bridge and the action to perform while copying.

        Args:
            host: Bridge whose ``save_to_sandbox`` drives this sandbox.
            copy_action: ``drop_host_document`` clears the host's document, as a concurrent
                ``close_file`` would; ``consume_source`` moves the source file away.
        """
        super().__init__()
        self.host = host
        self.copy_action = copy_action
        self.sources: list[str] = []

    def create(self, *, sandbox_type: str) -> dict[str, Any]:
        """Return a provisioned-instance record naming the requested sandbox type.

        Args:
            sandbox_type: Sandbox flavor requested by the bridge under test.

        Returns:
            dict[str, Any]: Instance record whose identifier embeds ``sandbox_type``.
        """
        return {"instance_id": f"{sandbox_type}-host-5", "type": sandbox_type, "status": "running"}

    def copy_to(self, *, instance_id: str, source: str, dest: str) -> dict[str, Any]:
        """Perform the configured host-side action instead of a plain copy.

        Args:
            instance_id: Identifier previously returned by ``create``.
            source: Host-side file handed over by the bridge.
            dest: Destination path for a consumed source file.

        Returns:
            dict[str, Any]: Copy outcome record.
        """
        self.sources.append(source)
        if self.copy_action == "drop_host_document":
            self.host.document = None
            gc.collect()
        else:
            host_document = self.host.document
            if host_document is not None:
                host_document.close()
            shutil.move(source, dest)
        return {"instance_id": instance_id, "dest": dest, "status": "copied"}


class _RunnerSandbox(HexEditorBridge):
    """Sandbox bridge with a synchronous ``run_binary`` hook returning a configured result."""

    def __init__(self, result: object) -> None:
        """Remember the result to hand back and start with no recorded invocation.

        Args:
            result: Value returned by every ``run_binary`` call.
        """
        super().__init__()
        self.result = result
        self.calls: list[dict[str, object]] = []

    def run_binary(self, *, binary_path: str, args: list[str] | None, sandbox_type: str, time_limit: int) -> object:
        """Record the invocation and return the configured result.

        Args:
            binary_path: Host path of the binary under test.
            args: Argument list, or ``None`` when no arguments were given.
            sandbox_type: Sandbox flavor requested by the bridge.
            time_limit: Execution timeout in seconds.

        Returns:
            object: The configured result.
        """
        self.calls.append({
            "binary_path": binary_path,
            "args": args,
            "sandbox_type": sandbox_type,
            "time_limit": time_limit,
        })
        return self.result


def _method(owner: object, name: str) -> Callable[..., Any]:
    """Look up a private attribute of ``owner`` that must be callable.

    Args:
        owner: Object or class owning the attribute.
        name: Attribute name.

    Returns:
        Callable[..., Any]: The bound or static callable.

    Raises:
        TypeError: If the attribute is not callable.
    """
    value: object = getattr(owner, name)
    if not callable(value):
        msg = f"{owner!r}.{name} is not callable"
        raise TypeError(msg)
    return value


def _set_flag(owner: object, name: str, *, value: bool) -> None:
    """Assign a private boolean flag on ``owner``.

    Args:
        owner: Object whose flag is assigned.
        name: Attribute name.
        value: New flag value.
    """
    setattr(owner, name, value)


def _listing(directory: Path) -> list[Path]:
    """List the entries of a directory.

    Args:
        directory: Directory to list.

    Returns:
        list[Path]: Entries in directory order.
    """
    return list(directory.iterdir())


def _open_bytes(bridge: HexEditorBridge, data: bytes) -> intellicrack_hexcore.HexDocument:
    """Attach an in-memory ``HexDocument`` holding ``data`` to ``bridge``.

    Args:
        bridge: Bridge receiving the document.
        data: Document contents.

    Returns:
        intellicrack_hexcore.HexDocument: The attached document.
    """
    document = intellicrack_hexcore.HexDocument.open_bytes(data)
    bridge.document = document
    return document


def _open_path(bridge: HexEditorBridge, path: Path) -> None:
    """Attach a file-backed ``HexDocument`` for ``path`` to ``bridge``.

    Args:
        bridge: Bridge receiving the document.
        path: File to open.
    """
    bridge.document = intellicrack_hexcore.HexDocument.open(str(path))


def _logged_events(captured: Sequence[Mapping[str, Any]]) -> list[str]:
    """Reduce captured structlog entries to their event names.

    Args:
        captured: Entries collected by ``structlog.testing.capture_logs``.

    Returns:
        list[str]: Event name of each entry in emission order.
    """
    return [str(entry.get("event")) for entry in captured]


def _redirect_tempdir(monkeypatch: pytest.MonkeyPatch, directory: Path) -> Path:
    """Point ``tempfile`` at a fresh directory under ``directory``.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        directory: Parent directory for the scratch directory.

    Returns:
        Path: The scratch directory ``tempfile.mkstemp`` will now use.
    """
    scratch = directory / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return scratch


def _sandbox_registry(directory: Path, sandbox: HexEditorBridge) -> ToolRegistry:
    """Build a real ``ToolRegistry`` with ``sandbox`` registered under ``ToolName.SANDBOX``.

    Args:
        directory: Parent directory for the registry's tool directory.
        sandbox: Bridge to register as the sandbox.

    Returns:
        ToolRegistry: Registry whose ``get(ToolName.SANDBOX)`` returns ``sandbox``.
    """
    registry = ToolRegistry(directory / "tools")
    registry.register_bridge(ToolName.SANDBOX, sandbox)
    return registry


def _vint(value: int) -> bytes:
    """Encode ``value`` as the variable-length integer shared by the BPS and UPS formats.

    Args:
        value: Non-negative integer.

    Returns:
        bytes: Seven payload bits per byte, the final byte flagged with ``0x80``, and one
        subtracted after every continuation byte.
    """
    out = bytearray()
    remaining = value
    while True:
        low = remaining & 0x7F
        remaining >>= 7
        if remaining == 0:
            out.append(0x80 | low)
            return bytes(out)
        out.append(low)
        remaining -= 1


def _bps_patch(source: bytes, target_size: int, actions: bytes, target_crc: int) -> bytes:
    """Assemble a BPS1 patch from its header, actions and CRC footer.

    Args:
        source: Source file contents; sets the declared size and the source checksum.
        target_size: Declared size of the patched file.
        actions: Encoded action stream.
        target_crc: Target checksum to store.

    Returns:
        bytes: Complete patch with a correct trailing patch checksum.
    """
    body = b"BPS1" + _vint(len(source)) + _vint(target_size) + _vint(0) + actions
    body += struct.pack("<II", zlib.crc32(source), target_crc)
    return body + struct.pack("<I", zlib.crc32(body))


def _ups_patch(source: bytes, target: bytes, hunks: bytes, *, target_crc: int | None = None) -> bytes:
    """Assemble a UPS1 patch from its header, hunks and CRC footer.

    Args:
        source: Source file contents.
        target: Patched file contents.
        hunks: Encoded relative-offset and XOR-byte hunks.
        target_crc: Target checksum to store; defaults to the CRC-32 of ``target``.

    Returns:
        bytes: Complete patch with a correct trailing patch checksum.
    """
    stored_target_crc = zlib.crc32(target) if target_crc is None else target_crc
    body = b"UPS1" + _vint(len(source)) + _vint(len(target)) + hunks
    body += struct.pack("<II", zlib.crc32(source), stored_target_crc)
    return body + struct.pack("<I", zlib.crc32(body))


def _double_view(parsed: int) -> str:
    """Render the 64-bit pattern ``parsed`` as the text of a little-endian IEEE-754 double.

    Args:
        parsed: Unsigned 64-bit integer.

    Returns:
        str: ``str`` of the decoded double.
    """
    return str(struct.unpack("<d", struct.pack("<Q", parsed))[0])


_TARGET_READ_PATCH = _bps_patch(b"", 4, _vint((3 << 2) | 1) + b"abcd", zlib.crc32(b"abcd"))
_RELOCATED_SOURCE = b"AAAABBBB"
_RELOCATED_TARGET = b"BBBBAAAA"

_UPS_CASES: list[tuple[bytes, bytes, bytes]] = [
    (b"ABCDEFGH", b"ABXDEFGH", b"\x82\x1b\x00"),
    (b"SAME", b"SAME", b""),
    (b"AB", b"ABCD", b"\x82\x43\x44"),
    (b"ABCDEF", b"ABC", b"\x83\x44\x45\x46"),
    (b"0123456789", b"0X2345Y789", b"\x81\x69\x00\x83\x6f\x00"),
    (b"abcdef", b"aXYdef", b"\x81\x3a\x3a\x00"),
]
_UPS_CASE_IDS = ["single-hunk", "identical", "growth", "shrink", "two-hunks", "multi-byte-hunk"]


@pytest.fixture
def hex_bridge() -> Iterator[HexEditorBridge]:
    """Provide an uninitialized ``HexEditorBridge`` and release any document afterwards.

    Yields:
        HexEditorBridge: A bridge with no document attached.
    """
    bridge = HexEditorBridge()
    try:
        yield bridge
    finally:
        bridge.document = None
        gc.collect()


@pytest.fixture
def observed(hex_bridge: HexEditorBridge) -> tuple[HexEditorBridge, _EventLog]:
    """Attach a state holder with a recording observer to the bridge.

    Args:
        hex_bridge: Bridge under test.

    Returns:
        tuple[HexEditorBridge, _EventLog]: The bridge and the log of events its holder delivers.
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id=_OBSERVER_ID)
    hex_bridge.set_state_holder(holder)
    return hex_bridge, log


@pytest.mark.parametrize(
    ("value", "from_base", "expected"),
    [
        pytest.param("0b1011", "binary", 11, id="binary-prefixed"),
        pytest.param("0B1011", "binary", 11, id="binary-upper-prefix"),
        pytest.param("1011", "binary", 11, id="binary-bare"),
        pytest.param("0o17", "octal", 15, id="octal-prefixed"),
        pytest.param("0O17", "octal", 15, id="octal-upper-prefix"),
        pytest.param("17", "octal", 15, id="octal-bare"),
        pytest.param("42", "decimal", 42, id="decimal"),
        pytest.param("-7", "decimal", -7, id="decimal-negative"),
    ],
)
def test_parse_base_value_reads_the_value_in_the_requested_base(value: str, from_base: str, expected: int) -> None:
    """Binary, octal and decimal hints parse with and without their radix prefix.

    Args:
        value: Text to parse.
        from_base: Base hint.
        expected: Integer the text denotes in that base.
    """
    assert _method(HexEditorBridge, "_parse_base_value")(value, from_base) == expected


@pytest.mark.parametrize(
    ("value", "from_base"),
    [
        pytest.param("102", "binary", id="binary-digit-two"),
        pytest.param("19", "octal", id="octal-digit-nine"),
        pytest.param("12a", "decimal", id="decimal-letter"),
    ],
)
def test_parse_base_value_rejects_digits_outside_the_base(value: str, from_base: str) -> None:
    """A digit that does not exist in the hinted base raises ``ValueError``.

    Args:
        value: Text to parse.
        from_base: Base hint.
    """
    with pytest.raises(ValueError, match="invalid literal"):
        _method(HexEditorBridge, "_parse_base_value")(value, from_base)


@pytest.mark.parametrize(
    ("parsed", "expected"),
    [
        pytest.param(0x3FF0000000000000, {"float64_le": "1.0"}, id="double-one-only"),
        pytest.param(0x7FF0000000000000, {}, id="double-infinity"),
        pytest.param(0x7FF8000000000000, {}, id="double-nan"),
        pytest.param(1 << 64, {}, id="beyond-64-bits"),
        pytest.param(-1, {}, id="negative"),
        pytest.param(0x3F800000, {"float32_le": "1.0", "float64_le": _double_view(0x3F800000)}, id="single-one"),
        pytest.param(0x7F800000, {"float64_le": _double_view(0x7F800000)}, id="single-infinity"),
        pytest.param(1 << 32, {"float64_le": _double_view(1 << 32)}, id="just-beyond-32-bits"),
    ],
)
def test_populate_float_views_follows_the_width_and_finiteness_of_the_value(parsed: int, expected: dict[str, str]) -> None:
    """The single view needs a 32-bit value and the double view a 64-bit one; infinities and NaN are dropped.

    Args:
        parsed: Integer under inspection.
        expected: Float views the helper must add.
    """
    result: dict[str, str] = {}

    _method(HexEditorBridge, "_populate_float_views")(parsed, result)

    assert result == expected


def test_match_die_pattern_defaults_a_string_entry_to_the_entry_point_window() -> None:
    """A bare string pattern is searched in the entry-point bytes, not in the whole document."""
    results: list[dict[str, Any]] = []
    entry_point = b"\x00\x00\xde\xad\xbe\xef\x00"
    whole_document = b"\xde\xad\xbe\xef" + bytes(16)

    _method(HexEditorBridge, "_match_die_pattern")("DE AD BE EF", ("PackerX", "packer", "1.2"), entry_point, whole_document, results)

    assert results == [
        {"name": "PackerX", "type": "packer", "version": "1.2", "offset": 2, "details": "Entry point match at +2"},
    ]


def test_match_die_pattern_any_offset_searches_the_whole_document() -> None:
    """A dict pattern with offset ``any`` is found in the document bytes even when the entry point lacks it."""
    results: list[dict[str, Any]] = []
    whole_document = b"\x00" * 5 + b"\xca\xfe" + b"\x00" * 3

    _method(HexEditorBridge, "_match_die_pattern")(
        {"pattern": "CA FE", "offset": "any"},
        ("Cafe", "protector", "2.0"),
        b"\x00" * 4,
        whole_document,
        results,
    )
    _method(HexEditorBridge, "_match_die_pattern")(
        {"pattern": "BA BE", "offset": "any"},
        ("Babe", "protector", "2.0"),
        b"\x00" * 4,
        whole_document,
        results,
    )

    assert results == [
        {"name": "Cafe", "type": "protector", "version": "2.0", "offset": 5, "details": "Full scan match at 0x5"},
    ]


@pytest.mark.parametrize(
    ("offset_spec", "pattern", "expected_offset"),
    [
        pytest.param("0x4", "04 05", 4, id="hex-offset-hit"),
        pytest.param("4", "04 05", 4, id="decimal-offset-hit"),
        pytest.param("0x2", "FF", None, id="different-bytes"),
        pytest.param("0x5", "05 06", None, id="runs-past-the-end"),
    ],
)
def test_match_die_pattern_fixed_offset_compares_bytes_at_that_offset(offset_spec: str, pattern: str, expected_offset: int | None) -> None:
    """A numeric offset matches only when the pattern equals the bytes there and fits in the document.

    Args:
        offset_spec: Offset text from the signature.
        pattern: Hex pattern from the signature.
        expected_offset: Offset the match must report, or ``None`` for no match.
    """
    results: list[dict[str, Any]] = []

    _method(HexEditorBridge, "_match_die_pattern")(
        {"pattern": pattern, "offset": offset_spec},
        ("Fixed", "compiler", "3.1"),
        b"",
        bytes(range(6)),
        results,
    )

    if expected_offset is None:
        assert results == []
    else:
        assert results == [
            {
                "name": "Fixed",
                "type": "compiler",
                "version": "3.1",
                "offset": expected_offset,
                "details": f"Fixed offset match at 0x{expected_offset:X}",
            },
        ]


@pytest.mark.parametrize(
    "pattern_info",
    [
        pytest.param(42, id="unsupported-type"),
        pytest.param({"pattern": "ZZ", "offset": "any"}, id="invalid-hex"),
        pytest.param({"pattern": "00", "offset": "not-a-number"}, id="invalid-offset"),
    ],
)
def test_match_die_pattern_ignores_malformed_entries(pattern_info: object) -> None:
    """Entries that are neither string nor dict, carry invalid hex, or carry an unparsable offset add nothing.

    Args:
        pattern_info: Malformed signature entry.
    """
    results: list[dict[str, Any]] = []

    _method(HexEditorBridge, "_match_die_pattern")(pattern_info, ("Bad", "packer", "0"), bytes(8), bytes(8), results)

    assert results == []


def test_compute_doc_md5_streaming_requires_a_document(hex_bridge: HexEditorBridge) -> None:
    """Hashing without an open document raises ``RuntimeError``.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        _method(hex_bridge, "_compute_doc_md5_streaming")()


@pytest.mark.parametrize("chunk_size", [0, -3])
def test_compute_doc_md5_streaming_rejects_a_non_positive_chunk_size(hex_bridge: HexEditorBridge, chunk_size: int) -> None:
    """A zero or negative chunk size is rejected with ``ValueError`` naming the value.

    Args:
        hex_bridge: Bridge under test.
        chunk_size: Invalid chunk size.
    """
    _open_bytes(hex_bridge, b"payload")

    with pytest.raises(ValueError, match=f"chunk_size must be positive, got {chunk_size}"):
        _method(hex_bridge, "_compute_doc_md5_streaming")(chunk_size)


def test_compute_doc_md5_streaming_matches_hashlib_across_chunk_boundaries(hex_bridge: HexEditorBridge) -> None:
    """A chunk size that does not divide the document length still yields the MD5 of all bytes.

    Args:
        hex_bridge: Bridge under test.
    """
    data = bytes(range(256)) + b"tail"
    _open_bytes(hex_bridge, data)

    digest = _method(hex_bridge, "_compute_doc_md5_streaming")(7)

    assert digest == hashlib.md5(data, usedforsecurity=False).hexdigest()


def test_scan_clamav_hdb_requires_a_document(hex_bridge: HexEditorBridge) -> None:
    """Scanning hash signatures without an open document raises ``RuntimeError``.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        _method(hex_bridge, "_scan_clamav_hdb")(["00:1:Name"])


def test_scan_clamav_hdb_skips_malformed_lines_and_reports_hash_and_size_matches(hex_bridge: HexEditorBridge) -> None:
    """Short lines and non-numeric sizes are skipped; a signature must match both hash and size.

    Args:
        hex_bridge: Bridge under test.
    """
    data = b"clamav hash sample"
    _open_bytes(hex_bridge, data)
    digest = hashlib.md5(data, usedforsecurity=False).hexdigest()
    lines = [
        "only:two",
        f"{digest}:not-a-number:Broken.Size",
        f"{digest.upper()}:{len(data)}:Upper.Case",
        f"{digest}:{len(data) + 1}:Wrong.Size",
        f"{'0' * 32}:{len(data)}:Wrong.Hash",
        f"  {digest}:{len(data)}:Exact.Match\n",
    ]

    results = cast("list[dict[str, Any]]", _method(hex_bridge, "_scan_clamav_hdb")(lines))

    assert results == [
        {"name": name, "type": "hash", "version": "", "offset": 0, "details": f"MD5 hash match (size={len(data)})"}
        for name in ("Upper.Case", "Exact.Match")
    ]


def test_scan_clamav_ndb_applies_each_offset_form_and_skips_unusable_signatures(hex_bridge: HexEditorBridge) -> None:
    """Anywhere, entry-point and fixed-offset signatures match as documented; unusable ones are skipped.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, bytes.fromhex("00112233445566778899"))
    lines = [
        "TooShort:0:*",
        "Empty:0:*:",
        "BadHex:0:*:ZZ",
        "OddHex:0:*:1",
        "EpHit:0:EP+0:00 11 22",
        "EpMiss:0:EP+0:11 22",
        "AnyHit:0:*:66 77",
        "FixedHit:0:3:33 44 ??",
        "FixedHex:0:0x05:55*77",
        "FixedEdge:0:8:88 99",
        "FixedMiss:0:1:FF",
        "FixedBadOffset:0:zz:00",
        "FixedTooFar:0:9:99 AA",
    ]

    results = cast("list[dict[str, Any]]", _method(hex_bridge, "_scan_clamav_ndb")(lines))

    assert [(r["name"], r["type"], r["offset"], r["details"]) for r in results] == [
        ("EpHit", "ndb", 0, "Entry point match"),
        ("AnyHit", "ndb", 6, "Pattern match at 0x6"),
        ("FixedHit", "ndb", 3, "Fixed offset match at 0x3"),
        ("FixedHex", "ndb", 5, "Fixed offset match at 0x5"),
        ("FixedEdge", "ndb", 8, "Fixed offset match at 0x8"),
    ]


@pytest.mark.parametrize("sig_hex", ["", "   ", "1", "ABC", "ZZ", "AB ZZ"])
def test_compile_clamav_ndb_pattern_rejects_empty_short_and_non_hex_patterns(sig_hex: str) -> None:
    """Empty patterns, a dangling nibble and non-hex pairs do not compile.

    Args:
        sig_hex: Raw NDB pattern field.
    """
    assert _method(HexEditorBridge, "_compile_clamav_ndb_pattern")(sig_hex) is None


def test_compile_clamav_ndb_pattern_translates_wildcards() -> None:
    """``??`` matches one arbitrary byte and ``*`` a gap of zero or more bytes."""
    compiled = _method(HexEditorBridge, "_compile_clamav_ndb_pattern")("AB ?? CD*EF")

    assert compiled is not None
    regex, min_len = compiled
    assert min_len == 4
    assert regex.match(b"\xab\x00\xcd\xef") is not None
    assert regex.match(b"\xab\xff\xcd\x01\x02\x03\xef") is not None
    assert regex.match(b"\xab\x00\xce\xef") is None


def test_compile_clamav_ndb_pattern_rejects_a_signed_pair() -> None:
    """A signed pair such as ``-1`` is not a hex byte, so the pattern is rejected rather than raising."""
    assert _method(HexEditorBridge, "_compile_clamav_ndb_pattern")("-1") is None


def test_load_source_via_mmap_reads_a_file_and_short_circuits_an_empty_one(tmp_path: Path) -> None:
    """A populated file is returned byte for byte and an empty file yields ``b""``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    populated = tmp_path / "populated.bin"
    populated.write_bytes(bytes(range(200)))
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    load = _method(HexEditorBridge, "_load_source_via_mmap")

    assert load(str(populated)) == bytes(range(200))
    assert load(str(empty)) == b""


@pytest.mark.parametrize(
    "name",
    [
        "_export_patches_bps_via_backend",
        "_export_patches_bps_pyfallback",
        "_export_patches_ups_via_backend",
        "_export_patches_ups_pyfallback",
    ],
)
def test_patch_exporters_require_a_document(hex_bridge: HexEditorBridge, tmp_path: Path, name: str) -> None:
    """Every BPS and UPS exporter raises ``RuntimeError`` when the document was closed.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
        name: Name of the exporter.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        _method(hex_bridge, name)(str(tmp_path / "original.bin"))


def test_ups_pyfallback_exporter_diffs_the_document_against_the_original_file(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """The pure-Python UPS exporter XOR-diffs the original file against the edited document.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    original = tmp_path / "original.bin"
    original.write_bytes(b"ABCDEFGH")
    _open_bytes(hex_bridge, b"ABXDEFGH")

    patch = _method(hex_bridge, "_export_patches_ups_pyfallback")(str(original))

    assert patch == _ups_patch(b"ABCDEFGH", b"ABXDEFGH", b"\x82\x1b\x00")


def test_decode_bps_var_int_returns_zero_without_consuming_when_the_position_is_at_the_end() -> None:
    """Decoding at or past the end of the data reads nothing: value zero, position unchanged."""
    decode = _method(HexEditorBridge, "_decode_bps_var_int")

    assert decode(b"", 0) == (0, 0)
    assert decode(b"\x85", 1) == (0, 1)


def test_emit_bps_copy_action_declines_when_fewer_than_a_word_of_target_remains(hex_bridge: HexEditorBridge) -> None:
    """With under four target bytes left no copy is emitted and nothing is consumed.

    Args:
        hex_bridge: Bridge under test.
    """
    patch = bytearray()
    pending = bytearray(b"queued")
    state = {"out_pos": 0, "src_rel": 0, "tgt_rel": 0}

    consumed = _method(hex_bridge, "_emit_bps_copy_action")(patch, pending, b"ABCDEFGH", b"XYZ", {}, {}, state)

    assert consumed == 0
    assert patch == b""
    assert pending == b"queued"
    assert state == {"out_pos": 0, "src_rel": 0, "tgt_rel": 0}


def test_find_best_bps_match_cap_excludes_candidates_at_or_after_it() -> None:
    """Target-against-target matching stops at the first candidate offset not below ``cap``."""
    buffer = b"ABCD" + b"ABCDEFGH"
    find = _method(HexEditorBridge, "_find_best_bps_match")

    assert find(buffer, buffer, 4, [0, 4], 4) == (4, 0)
    assert find(buffer, buffer, 4, [0, 4], 5) == (8, 4)
    assert find(buffer, buffer, 4, [0, 4], None) == (8, 4)


def test_find_best_bps_match_keeps_the_longest_run_regardless_of_candidate_order() -> None:
    """A shorter later candidate never replaces a longer earlier one, and a longer later one does."""
    haystack = b"ABCDEFGH" + b"ABCDxxxx"
    needle = b"ABCDEFGH"
    find = _method(HexEditorBridge, "_find_best_bps_match")

    assert find(haystack, needle, 0, [0, 8], None) == (8, 0)
    assert find(haystack, needle, 0, [8, 0], None) == (8, 0)
    assert find(haystack, needle, 0, [], None) == (0, 0)
    assert find(haystack, needle, 0, None, None) == (0, 0)


def test_build_bps_patch_emits_source_copy_for_runs_found_elsewhere_in_the_source(hex_bridge: HexEditorBridge) -> None:
    """Swapped halves become two ``SourceCopy`` actions with signed, relative offsets.

    Args:
        hex_bridge: Bridge under test.
    """
    actions = _vint((3 << 2) | 2) + _vint(4 << 1) + _vint((3 << 2) | 2) + _vint((8 << 1) | 1)
    expected = _bps_patch(_RELOCATED_SOURCE, 8, actions, zlib.crc32(_RELOCATED_TARGET))

    patch = _method(hex_bridge, "_build_bps_patch")(_RELOCATED_SOURCE, _RELOCATED_TARGET)

    assert patch == expected
    assert _method(hex_bridge, "_apply_bps_patch")(patch, _RELOCATED_SOURCE) == _RELOCATED_TARGET


def test_bps_patch_round_trips_mixed_relocated_repeated_and_novel_data(hex_bridge: HexEditorBridge) -> None:
    """Applying a built patch to its source reproduces the target; the footer stores the three checksums.

    Args:
        hex_bridge: Bridge under test.
    """
    source = bytes((i * 37 + 11) % 251 for i in range(300))
    target = source[120:180] + b"\xaa" * 24 + source[0:50] + b"NOVELBYTES" + source[200:260] + source[10:30] * 2 + b"\x01\x02"

    patch = _method(hex_bridge, "_build_bps_patch")(source, target)

    assert _method(hex_bridge, "_apply_bps_patch")(patch, source) == target
    assert struct.unpack_from("<III", patch, len(patch) - 12) == (zlib.crc32(source), zlib.crc32(target), zlib.crc32(patch[:-4]))


def test_apply_bps_patch_reports_a_target_checksum_mismatch(hex_bridge: HexEditorBridge) -> None:
    """A patch whose stored target checksum does not match the reconstructed bytes is rejected.

    Args:
        hex_bridge: Bridge under test.
    """
    actions = _vint((3 << 2) | 1) + b"abcd"
    corrupted = _bps_patch(b"", 4, actions, zlib.crc32(b"abce"))
    apply_patch = _method(hex_bridge, "_apply_bps_patch")

    assert apply_patch(_TARGET_READ_PATCH, b"") == b"abcd"
    with pytest.raises(ValueError, match="target CRC mismatch"):
        apply_patch(corrupted, b"")


@pytest.mark.parametrize(
    "patch",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"BPS1", id="header-only"),
        pytest.param(b"XPS1" + bytes(12), id="wrong-magic"),
    ],
)
def test_validate_bps_header_rejects_short_patches_and_wrong_magic(hex_bridge: HexEditorBridge, patch: bytes) -> None:
    """Patches under twelve bytes, or not starting with ``BPS1``, are invalid.

    Args:
        hex_bridge: Bridge under test.
        patch: Malformed patch.
    """
    with pytest.raises(ValueError, match="invalid BPS patch"):
        _method(hex_bridge, "_validate_bps_header")(patch, b"")


def test_validate_bps_header_rejects_a_corrupted_patch_and_a_wrong_source(hex_bridge: HexEditorBridge) -> None:
    """A flipped patch byte fails the patch checksum and a different source fails the source checksum.

    Args:
        hex_bridge: Bridge under test.
    """
    validate = _method(hex_bridge, "_validate_bps_header")
    flipped = bytearray(_TARGET_READ_PATCH)
    flipped[-1] ^= 0xFF

    validate(_TARGET_READ_PATCH, b"")
    with pytest.raises(ValueError, match="BPS patch CRC mismatch"):
        validate(bytes(flipped), b"")
    with pytest.raises(ValueError, match="source CRC mismatch"):
        validate(_TARGET_READ_PATCH, b"x")


def test_exec_bps_command_source_read_leaves_target_bytes_the_source_cannot_supply(hex_bridge: HexEditorBridge) -> None:
    """A ``SourceRead`` longer than the source copies what exists and still advances the output position.

    Args:
        hex_bridge: Bridge under test.
    """
    target = bytearray(4)
    state = [0, 0, 0]

    new_pos = _method(hex_bridge, "_exec_bps_command")((3 << 2) | 0, b"", b"AB", target, 0, 0, state)

    assert new_pos == 0
    assert bytes(target) == b"AB\x00\x00"
    assert state == [4, 0, 0]


def test_exec_bps_command_target_read_stops_at_the_footer(hex_bridge: HexEditorBridge) -> None:
    """A ``TargetRead`` never consumes bytes at or beyond the footer position.

    Args:
        hex_bridge: Bridge under test.
    """
    target = bytearray(3)
    state = [0, 0, 0]

    new_pos = _method(hex_bridge, "_exec_bps_command")((2 << 2) | 1, b"AB!!!", b"", target, 0, 2, state)

    assert new_pos == 2
    assert bytes(target) == b"AB\x00"
    assert state == [2, 0, 0]


@pytest.mark.parametrize(
    ("encoded_delta", "start", "expected", "final_state"),
    [
        pytest.param(2 << 1, 0, b"234", [3, 5, 0], id="forward"),
        pytest.param((2 << 1) | 1, 6, b"456", [3, 7, 0], id="backward"),
        pytest.param((1 << 1) | 1, 0, b"\x0001", [3, 2, 0], id="before-the-start"),
    ],
)
def test_exec_bps_command_source_copy_applies_a_signed_relative_offset(
    hex_bridge: HexEditorBridge,
    encoded_delta: int,
    start: int,
    expected: bytes,
    final_state: list[int],
) -> None:
    """A ``SourceCopy`` moves the source cursor by the signed delta, then copies; reads before offset zero are skipped.

    Args:
        hex_bridge: Bridge under test.
        encoded_delta: Delta as encoded in the stream: magnitude shifted left, sign in bit zero.
        start: Source cursor before the command.
        expected: Target bytes after the command.
        final_state: Cursor triple after the command.
    """
    patch = _vint(encoded_delta)
    target = bytearray(3)
    state = [0, start, 0]

    new_pos = _method(hex_bridge, "_exec_bps_command")((2 << 2) | 2, patch, b"0123456789", target, 0, len(patch), state)

    assert new_pos == len(patch)
    assert bytes(target) == expected
    assert state == final_state


@pytest.mark.parametrize(
    ("action_length", "encoded_delta", "initial", "output_pos", "expected", "final_state"),
    [
        pytest.param(4, 0, b"ABCD\x00\x00\x00\x00", 4, b"ABCDABCD", [8, 0, 4], id="copy-earlier-output"),
        pytest.param(3, 0, b"A\x00\x00\x00", 1, b"AAAA", [4, 0, 3], id="overlapping-run"),
        pytest.param(2, (1 << 1) | 1, b"AB\x00\x00", 2, b"AB\x00A", [4, 0, 1], id="before-the-start"),
    ],
)
def test_exec_bps_command_target_copy_reads_back_from_the_output(
    hex_bridge: HexEditorBridge,
    action_length: int,
    encoded_delta: int,
    initial: bytes,
    output_pos: int,
    expected: bytes,
    final_state: list[int],
) -> None:
    """A ``TargetCopy`` replays earlier output byte by byte, so a copy may overlap itself; out-of-range reads are skipped.

    Args:
        hex_bridge: Bridge under test.
        action_length: Number of bytes the command copies.
        encoded_delta: Delta as encoded in the stream.
        initial: Target buffer before the command.
        output_pos: Output position before the command.
        expected: Target buffer after the command.
        final_state: Cursor triple after the command.
    """
    patch = _vint(encoded_delta)
    target = bytearray(initial)
    state = [output_pos, 0, 0]

    new_pos = _method(hex_bridge, "_exec_bps_command")(((action_length - 1) << 2) | 3, patch, b"", target, 0, len(patch), state)

    assert new_pos == len(patch)
    assert bytes(target) == expected
    assert state == final_state


@pytest.mark.parametrize(("source", "target", "hunks"), _UPS_CASES, ids=_UPS_CASE_IDS)
def test_build_ups_patch_encodes_relative_offsets_and_xor_runs(
    hex_bridge: HexEditorBridge,
    source: bytes,
    target: bytes,
    hunks: bytes,
) -> None:
    """The UPS encoder emits size varints, relative-offset XOR hunks and the three checksums.

    Args:
        hex_bridge: Bridge under test.
        source: Original contents.
        target: Patched contents.
        hunks: Hunk bytes worked out by hand from the XOR of source and target.
    """
    assert _method(hex_bridge, "_build_ups_patch")(source, target) == _ups_patch(source, target, hunks)


@pytest.mark.parametrize(("source", "target", "hunks"), _UPS_CASES, ids=_UPS_CASE_IDS)
def test_apply_ups_patch_reconstructs_the_target_including_resizes(
    hex_bridge: HexEditorBridge,
    source: bytes,
    target: bytes,
    hunks: bytes,
) -> None:
    """Applying a hand-assembled UPS patch yields the target for equal, grown and shrunk files.

    Args:
        hex_bridge: Bridge under test.
        source: Original contents.
        target: Patched contents.
        hunks: Hunk bytes worked out by hand from the XOR of source and target.
    """
    assert _method(hex_bridge, "_apply_ups_patch")(_ups_patch(source, target, hunks), source) == target


@pytest.mark.parametrize(
    "patch",
    [
        pytest.param(b"UPS1" + bytes(5), id="too-short"),
        pytest.param(b"BPS1" + bytes(20), id="wrong-magic"),
    ],
)
def test_apply_ups_patch_rejects_short_patches_and_wrong_magic(hex_bridge: HexEditorBridge, patch: bytes) -> None:
    """Patches under sixteen bytes, or not starting with ``UPS1``, are invalid.

    Args:
        hex_bridge: Bridge under test.
        patch: Malformed patch.
    """
    with pytest.raises(ValueError, match="invalid UPS patch"):
        _method(hex_bridge, "_apply_ups_patch")(patch, b"")


def test_apply_ups_patch_verifies_the_patch_source_and_target_checksums(hex_bridge: HexEditorBridge) -> None:
    """Each of the three stored checksums is enforced with its own error.

    Args:
        hex_bridge: Bridge under test.
    """
    apply_patch = _method(hex_bridge, "_apply_ups_patch")
    source, target, hunks = b"ABCDEFGH", b"ABXDEFGH", b"\x82\x1b\x00"
    valid = _ups_patch(source, target, hunks)
    flipped = bytearray(valid)
    flipped[5] ^= 0xFF
    wrong_target_crc = _ups_patch(source, target, hunks, target_crc=zlib.crc32(b"ABYDEFGH"))

    with pytest.raises(ValueError, match="UPS patch CRC mismatch"):
        apply_patch(bytes(flipped), source)
    with pytest.raises(ValueError, match="source CRC mismatch"):
        apply_patch(valid, b"ABCDEFGX")
    with pytest.raises(ValueError, match="target CRC mismatch"):
        apply_patch(wrong_target_crc, source)


@pytest.mark.asyncio
async def test_open_file_requires_the_hexcore_backend(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """With the backend flag cleared, opening a file raises ``RuntimeError`` and attaches nothing.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    _set_flag(hex_bridge, "_hexcore_available", value=False)

    with pytest.raises(RuntimeError, match="intellicrack_hexcore not installed"):
        await hex_bridge.open_file(str(sample))

    assert hex_bridge.document is None
    assert hex_bridge.state.binary_loaded is False


@pytest.mark.asyncio
async def test_adopt_document_replaces_the_active_document_and_resets_cursor_and_selection(
    observed: tuple[HexEditorBridge, _EventLog],
    tmp_path: Path,
) -> None:
    """Adopting a document binds it and the path, clears cursor and selection, and stays silent on the state holder.

    Args:
        observed: Bridge with an attached observer.
        tmp_path: Pytest temporary directory.
    """
    bridge, log = observed
    _open_bytes(bridge, b"previous")
    bridge.update_cursor_from_gui(5)
    await bridge.select_range(1, 2)
    log.events.clear()
    adopted = intellicrack_hexcore.HexDocument.open_bytes(b"adopted")
    path = tmp_path / "adopted.bin"

    bridge.adopt_document(cast("HexDocumentFull", adopted), path)

    assert bridge.document is adopted
    assert bridge.state.binary_loaded is True
    assert bridge.state.target_path == path
    assert await bridge.get_document_info() == {"file_path": None, "size": 7, "modified": False, "cursor": 0, "selection": None}
    assert await bridge.read_bytes(0, 7) == "61 64 6F 70 74 65 64"
    assert log.events == []


@pytest.mark.asyncio
async def test_save_requires_a_document(hex_bridge: HexEditorBridge) -> None:
    """Saving with no open document raises ``RuntimeError``.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.save()


@pytest.mark.asyncio
async def test_save_without_a_path_needs_a_document_that_has_one(hex_bridge: HexEditorBridge) -> None:
    """An in-memory document has no backing path, so ``save()`` points the caller at ``save_as``.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, b"in memory")

    with pytest.raises(RuntimeError, match="no file path; use save_as"):
        await hex_bridge.save()


@pytest.mark.asyncio
async def test_save_without_a_path_writes_back_to_the_documents_file_and_announces_it(
    observed: tuple[HexEditorBridge, _EventLog],
    tmp_path: Path,
) -> None:
    """``save()`` writes the document's bytes to its own file, rebinds the target and notifies observers.

    Args:
        observed: Bridge with an attached observer.
        tmp_path: Pytest temporary directory.
    """
    bridge, log = observed
    target = tmp_path / "writeback.bin"
    target.write_bytes(b"")
    _open_path(bridge, target)
    await bridge.insert_bytes(0, "DE AD BE EF")
    log.events.clear()

    saved = await bridge.save()

    assert saved is True
    assert target.read_bytes() == b"\xde\xad\xbe\xef"
    assert bridge.state.target_path == target
    assert (await bridge.get_document_info())["modified"] is False
    assert log.events == [
        (HexDocumentEvent.DOCUMENT_OPENED, {"file_path": str(target), "size": 4}),
        (HexDocumentEvent.DOCUMENT_SAVED, {"path": str(target)}),
    ]


@pytest.mark.asyncio
async def test_save_as_writes_a_new_file_and_rebinds_the_target_path(
    observed: tuple[HexEditorBridge, _EventLog],
    tmp_path: Path,
) -> None:
    """``save_as`` leaves the original file alone, writes the edited bytes elsewhere and rebinds the document.

    Args:
        observed: Bridge with an attached observer.
        tmp_path: Pytest temporary directory.
    """
    bridge, log = observed
    original = tmp_path / "original.bin"
    original.write_bytes(b"0123456789")
    copy = tmp_path / "copy.bin"
    await bridge.open_file(str(original))
    await bridge.write_bytes(0, "FF")
    log.events.clear()

    saved = await bridge.save_as(str(copy))

    assert saved is True
    assert copy.read_bytes() == b"\xff123456789"
    assert original.read_bytes() == b"0123456789"
    assert bridge.state.target_path == copy
    assert log.events == [
        (HexDocumentEvent.DOCUMENT_OPENED, {"file_path": str(copy), "size": 10}),
        (HexDocumentEvent.DOCUMENT_SAVED, {"path": str(copy)}),
    ]


@pytest.mark.asyncio
async def test_get_context_for_ai_rejects_a_negative_bookmark_limit(hex_bridge: HexEditorBridge) -> None:
    """A negative bookmark cap is rejected with ``ValueError`` naming the value.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(ValueError, match="bookmark_limit must be non-negative, got -1"):
        await hex_bridge.get_context_for_ai(bookmark_limit=-1)


@pytest.mark.asyncio
async def test_get_context_for_ai_without_a_document_is_just_the_empty_document_info(hex_bridge: HexEditorBridge) -> None:
    """With nothing open the AI context carries only the empty document description.

    Args:
        hex_bridge: Bridge under test.
    """
    context = await hex_bridge.get_context_for_ai()

    assert context == {"file_path": None, "size": 0, "modified": False, "cursor": 0, "selection": None}


@pytest.mark.asyncio
async def test_save_to_sandbox_rejects_a_sandbox_bridge_without_create(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A registered sandbox bridge lacking ``create`` raises ``TypeError``.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    backing = tmp_path / "backing.bin"
    backing.write_bytes(b"backed by a file")
    _open_path(hex_bridge, backing)
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, HexEditorBridge()))

    with pytest.raises(TypeError, match="sandbox bridge does not support create"):
        await hex_bridge.save_to_sandbox(str(tmp_path / "dest.bin"))


@pytest.mark.asyncio
async def test_save_to_sandbox_leaves_no_temporary_file_when_the_sandbox_has_no_create(
    hex_bridge: HexEditorBridge,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The temporary copy made for an unsaved document does not outlive a rejected sandbox bridge.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture, used to point ``tempfile`` at a scratch directory.
    """
    scratch = _redirect_tempdir(monkeypatch, tmp_path)
    _open_bytes(hex_bridge, b"unsaved document")
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, HexEditorBridge()))

    try:
        with pytest.raises(TypeError, match="sandbox bridge does not support create"):
            await hex_bridge.save_to_sandbox(str(tmp_path / "dest.bin"))
        leftovers = _listing(scratch)
    finally:
        hex_bridge.document = None
        gc.collect()
        for leftover in _listing(scratch):
            with contextlib.suppress(OSError):
                leftover.unlink()

    assert leftovers == []


@pytest.mark.asyncio
async def test_save_to_sandbox_destroys_the_orphaned_instance_when_the_copy_fails(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A failed copy tears down the freshly created instance through a synchronous ``destroy`` hook.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    backing = tmp_path / "backing.bin"
    backing.write_bytes(b"backed by a file")
    _open_path(hex_bridge, backing)
    sandbox = _DestroyingSandbox()
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, sandbox))

    with capture_logs() as captured, pytest.raises(RuntimeError, match="copy refused for windows-orphan-3"):
        await hex_bridge.save_to_sandbox(str(tmp_path / "dest.bin"))

    assert sandbox.destroyed == ["windows-orphan-3"]
    destroyed_entries = [e for e in captured if e.get("event") == "save_to_sandbox_destroyed_orphan_instance"]
    assert [e["instance_id"] for e in destroyed_entries] == ["windows-orphan-3"]


@pytest.mark.asyncio
async def test_save_to_sandbox_survives_a_failing_destroy_and_still_raises_the_copy_error(
    hex_bridge: HexEditorBridge,
    tmp_path: Path,
) -> None:
    """A ``destroy`` that raises is logged and swallowed so the original copy failure reaches the caller.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    backing = tmp_path / "backing.bin"
    backing.write_bytes(b"backed by a file")
    _open_path(hex_bridge, backing)
    sandbox = _DestroyingSandbox(fail_destroy=True)
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, sandbox))

    with capture_logs() as captured, pytest.raises(RuntimeError, match="copy refused for windows-orphan-3"):
        await hex_bridge.save_to_sandbox(str(tmp_path / "dest.bin"))

    events = _logged_events(captured)
    assert sandbox.destroyed == ["windows-orphan-3"]
    assert "save_to_sandbox_failed_to_destroy_orphan_instance" in events
    assert "save_to_sandbox_destroyed_orphan_instance" not in events


@pytest.mark.asyncio
async def test_save_to_sandbox_without_a_destroy_hook_only_reports_the_copy_failure(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A sandbox bridge with no ``destroy`` is not asked to tear anything down; the copy error propagates unchanged.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    backing = tmp_path / "backing.bin"
    backing.write_bytes(b"backed by a file")
    _open_path(hex_bridge, backing)
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, _FailingCopySandbox()))

    with capture_logs() as captured, pytest.raises(RuntimeError, match="copy refused for windows-orphan-3"):
        await hex_bridge.save_to_sandbox(str(tmp_path / "dest.bin"))

    events = _logged_events(captured)
    assert "save_to_sandbox_failed_to_destroy_orphan_instance" not in events
    assert "save_to_sandbox_destroyed_orphan_instance" not in events


@pytest.mark.asyncio
async def test_save_to_sandbox_tolerates_the_document_being_closed_during_the_copy(
    hex_bridge: HexEditorBridge,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A document closed by someone else while the copy runs does not break the temporary-file cleanup.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture, used to point ``tempfile`` at a scratch directory.
    """
    scratch = _redirect_tempdir(monkeypatch, tmp_path)
    hex_bridge.document = intellicrack_hexcore.HexDocument.open_bytes(b"in-memory sandbox payload")
    sandbox = _HostActionSandbox(hex_bridge, copy_action="drop_host_document")
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, sandbox))
    dest = str(tmp_path / "dest.bin")

    try:
        result = await hex_bridge.save_to_sandbox(dest, sandbox_type="qemu")
    finally:
        for leftover in _listing(scratch):
            with contextlib.suppress(OSError):
                leftover.unlink()

    assert result == {"sandbox_path": dest, "status": "copied", "instance_id": "qemu-host-5"}
    assert hex_bridge.document is None


@pytest.mark.asyncio
async def test_save_to_sandbox_logs_and_ignores_a_temporary_file_the_sandbox_already_took(
    hex_bridge: HexEditorBridge,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the sandbox bridge moves the temporary file away, the failed cleanup is a warning, not an error.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture, used to point ``tempfile`` at a scratch directory.
    """
    scratch = _redirect_tempdir(monkeypatch, tmp_path)
    payload = b"in-memory sandbox payload"
    hex_bridge.document = intellicrack_hexcore.HexDocument.open_bytes(payload)
    sandbox = _HostActionSandbox(hex_bridge, copy_action="consume_source")
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, sandbox))
    dest = tmp_path / "taken.bin"

    with capture_logs() as captured:
        result = await hex_bridge.save_to_sandbox(str(dest))

    assert result == {"sandbox_path": str(dest), "status": "copied", "instance_id": "windows-host-5"}
    assert dest.read_bytes() == payload
    assert _listing(scratch) == []
    cleanup_entries = [e for e in captured if e.get("event") == "tmp_file_cleanup_failed"]
    assert [e["log_level"] for e in cleanup_entries] == ["warning"]
    assert [Path(e["path"]) for e in cleanup_entries] == [Path(sandbox.sources[0])]


@pytest.mark.asyncio
async def test_test_in_sandbox_runs_a_synchronous_hook_and_returns_its_report(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A synchronous ``run_binary`` is invoked with the document path and split arguments, and its dict is returned.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"MZ binary")
    _open_path(hex_bridge, binary)
    report = {"exit_code": 3, "stdout": "ran", "stderr": ""}
    sandbox = _RunnerSandbox(report)
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, sandbox))

    result = await hex_bridge.test_in_sandbox(args="--flag value", sandbox_type="qemu", time_limit=7)

    assert result == report
    assert sandbox.calls == [{"binary_path": str(binary), "args": ["--flag", "value"], "sandbox_type": "qemu", "time_limit": 7}]


@pytest.mark.asyncio
async def test_test_in_sandbox_wraps_a_non_dict_report(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A ``run_binary`` that returns something other than a dict is reported as a failed run carrying its text.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"MZ binary")
    _open_path(hex_bridge, binary)
    sandbox = _RunnerSandbox("sandbox exploded")
    hex_bridge.set_tool_registry(_sandbox_registry(tmp_path, sandbox))

    result = await hex_bridge.test_in_sandbox()

    assert result == {"exit_code": -1, "stdout": "", "stderr": "sandbox exploded"}
    assert sandbox.calls[0]["args"] is None


@pytest.mark.asyncio
async def test_read_bytes_rejects_a_negative_offset(hex_bridge: HexEditorBridge) -> None:
    """A negative offset raises ``ValueError`` naming the value.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, b"abc")

    with pytest.raises(ValueError, match="read_bytes offset must be non-negative, got -1"):
        await hex_bridge.read_bytes(-1, 1)


@pytest.mark.asyncio
async def test_insert_and_delete_notify_observers_of_the_affected_range(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """Insertion and deletion each announce exactly the range they touched.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, b"ABCD")

    assert await bridge.insert_bytes(2, "FF EE") is True
    assert document.read(0, document.length()) == b"AB\xff\xeeCD"
    assert await bridge.delete_bytes(1, 2) is True
    assert document.read(0, document.length()) == b"A\xeeCD"

    assert log.events == [
        (HexDocumentEvent.DATA_MODIFIED, {"offset": 2, "length": 2, "source": _BRIDGE_SOURCE}),
        (HexDocumentEvent.DATA_MODIFIED, {"offset": 1, "length": 2, "source": _BRIDGE_SOURCE}),
    ]


@pytest.mark.asyncio
async def test_replace_bytes_that_changes_the_size_announces_the_whole_document(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """A replacement of a different length cannot be mapped to byte ranges, so the whole document is announced.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, b"xxAAyyAAzz")

    with capture_logs() as captured:
        replaced = await bridge.replace_bytes("41 41", "42")

    assert replaced == 2
    assert document.read(0, document.length()) == b"xxByyBzz"
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 0, "length": 8, "source": _BRIDGE_SOURCE})]
    assert "replace_bytes_using_wholesale_notify" in _logged_events(captured)


@pytest.mark.asyncio
async def test_replace_bytes_with_an_empty_pattern_replaces_nothing_and_stays_silent(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """An empty pattern matches nothing: zero replacements, unchanged bytes, no notification.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, b"ABCD")

    replaced = await bridge.replace_bytes("", "FF")

    assert replaced == 0
    assert document.read(0, 4) == b"ABCD"
    assert log.events == []


@pytest.mark.asyncio
async def test_undo_and_redo_report_false_without_a_document(hex_bridge: HexEditorBridge) -> None:
    """Without an open document there is nothing to undo or redo.

    Args:
        hex_bridge: Bridge under test.
    """
    assert await hex_bridge.undo() is False
    assert await hex_bridge.redo() is False


@pytest.mark.asyncio
async def test_undo_and_redo_restore_bytes_and_announce_the_whole_document(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """Undo reverts the last write, redo reapplies it, and each announces the full document range.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, b"ABCD")
    await bridge.write_bytes(0, "FF")
    log.events.clear()
    whole_document = (HexDocumentEvent.DATA_MODIFIED, {"offset": 0, "length": 4, "source": _BRIDGE_SOURCE})

    assert await bridge.undo() is True
    assert document.read(0, 4) == b"ABCD"
    assert log.events == [whole_document]
    log.events.clear()

    assert await bridge.redo() is True
    assert document.read(0, 4) == b"\xffBCD"
    assert log.events == [whole_document]
    log.events.clear()

    assert await bridge.redo() is False
    assert log.events == []


@pytest.mark.asyncio
async def test_copy_as_requires_a_document_and_a_known_format(hex_bridge: HexEditorBridge) -> None:
    """``copy_as`` raises ``RuntimeError`` with no document and ``ToolError`` for an unknown format.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.copy_as("hex")

    _open_bytes(hex_bridge, b"abc")
    with pytest.raises(ToolError, match=re.escape("unsupported output format: 'bogus'")):
        await hex_bridge.copy_as("bogus")


@pytest.mark.asyncio
async def test_fill_block_announces_the_filled_range(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """A repeating two-byte pattern fills the range and exactly that range is announced.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, bytes(8))

    assert await bridge.fill_block(1, 5, "AB CD") is True

    assert document.read(0, 8) == b"\x00\xab\xcd\xab\xcd\xab\x00\x00"
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 1, "length": 5, "source": _BRIDGE_SOURCE})]


@pytest.mark.asyncio
async def test_copy_move_and_swap_blocks_require_a_document(hex_bridge: HexEditorBridge) -> None:
    """Each block operation raises ``RuntimeError`` when no document is open.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.copy_block(0, 1, 2)
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.move_block(0, 1, 2)
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.swap_blocks(0, 1, 2, 1)


@pytest.mark.asyncio
async def test_copy_block_announces_the_destination_range(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """Copying a block duplicates it at the destination and announces the destination range.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, b"ABCDEFGHIJ")

    assert await bridge.copy_block(0, 3, 5) is True

    assert document.read(0, 10) == b"ABCDEABCIJ"
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 5, "length": 3, "source": _BRIDGE_SOURCE})]


@pytest.mark.asyncio
async def test_move_block_clears_the_source_and_announces_the_whole_document(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """Moving a block zeroes its source, writes it at the destination and announces the full document range.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, b"ABCDEFGHIJ")

    assert await bridge.move_block(0, 3, 5) is True

    assert document.read(0, 10) == b"\x00\x00\x00DEABCIJ"
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 0, "length": 10, "source": _BRIDGE_SOURCE})]


@pytest.mark.asyncio
async def test_swap_blocks_exchanges_the_blocks_and_announces_the_whole_document(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """Swapping two equal blocks exchanges their bytes and announces the full document range.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, b"ABCDEFGH")

    assert await bridge.swap_blocks(0, 2, 4, 2) is True

    assert document.read(0, 8) == b"EFCDABGH"
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 0, "length": 8, "source": _BRIDGE_SOURCE})]


@pytest.mark.asyncio
async def test_apply_arithmetic_requires_a_document(hex_bridge: HexEditorBridge) -> None:
    """Arithmetic on a selection raises ``RuntimeError`` when no document is open.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.apply_arithmetic_to_selection("xor", "FF")


@pytest.mark.asyncio
async def test_apply_arithmetic_rejects_an_unknown_operation(hex_bridge: HexEditorBridge) -> None:
    """An operation outside the supported set raises ``ToolError`` naming it and leaves the bytes alone.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"ABCD")
    await hex_bridge.select_range(0, 3)

    with pytest.raises(ToolError, match=re.escape("unknown arithmetic transform: 'rot13'")):
        await hex_bridge.apply_arithmetic_to_selection("rot13")

    assert document.read(0, 4) == b"ABCD"


@pytest.mark.asyncio
async def test_apply_arithmetic_inverts_the_selection_and_announces_it(observed: tuple[HexEditorBridge, _EventLog]) -> None:
    """The ``not`` operation inverts every selected byte and announces the selected range.

    Args:
        observed: Bridge with an attached observer.
    """
    bridge, log = observed
    document = _open_bytes(bridge, b"\x00\x0f\xf0\xff\x55")
    await bridge.select_range(1, 3)
    log.events.clear()

    outcome = await bridge.apply_arithmetic_to_selection("not")

    assert outcome == {"offset": 1, "length": 3, "operation": "not"}
    assert document.read(0, 5) == b"\x00\xf0\x0f\x00\x55"
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 1, "length": 3, "source": _BRIDGE_SOURCE})]
