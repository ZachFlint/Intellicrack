# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""IPS / IPS32 patch encoder and decoder helpers.

Implements the legacy IPS patch format and its IPS32 extension using the
shared field-size constants declared in :mod:`._base`. These helpers are
invoked by the patches mixin and by the hex editor bridge to produce and
consume IPS payloads in pure Python without depending on the Rust hexcore
extension.
"""

from __future__ import annotations

import struct
from typing import Final

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.hex_editor._base import (
    IPS32_OFFSET_SIZE,
    IPS_HEADER_SIZE,
    IPS_LENGTH_FIELD_SIZE,
    IPS_OFFSET_SIZE,
)


__all__ = [
    "IPS32_EOF_MARKER",
    "IPS32_EOF_MARKER_LEN",
    "IPS32_MAGIC",
    "IPS32_MAX_OFFSET",
    "IPS_EOF_MARKER",
    "IPS_EOF_MARKER_LEN",
    "IPS_MAGIC",
    "IPS_MAX_OFFSET",
    "IPS_MAX_RUN_LENGTH",
    "export_ips_patch",
    "import_ips_patch",
]


_logger = get_logger(__name__)


IPS_MAGIC: Final[bytes] = b"PATCH"
IPS32_MAGIC: Final[bytes] = b"IPS32"
IPS_EOF_MARKER: Final[bytes] = b"EOF"
IPS32_EOF_MARKER: Final[bytes] = b"EEOF"
IPS_EOF_MARKER_LEN: Final[int] = len(IPS_EOF_MARKER)
IPS32_EOF_MARKER_LEN: Final[int] = len(IPS32_EOF_MARKER)

IPS_MAX_OFFSET: Final[int] = (1 << (IPS_OFFSET_SIZE * 8)) - 1
IPS32_MAX_OFFSET: Final[int] = (1 << (IPS32_OFFSET_SIZE * 8)) - 1
IPS_MAX_RUN_LENGTH: Final[int] = (1 << (IPS_LENGTH_FIELD_SIZE * 8)) - 1


def _diff_runs(original_data: bytes, modified_data: bytes) -> list[tuple[int, bytes]]:
    """Compute contiguous diff runs between two byte sequences.

    Args:
        original_data: Original bytes.
        modified_data: Modified bytes; may be longer than ``original_data``.

    Returns:
        list[tuple[int, bytes]]: Ordered list of ``(offset, bytes)`` runs.
    """
    runs: list[tuple[int, bytes]] = []
    n_orig = len(original_data)
    n_mod = len(modified_data)
    common = min(n_orig, n_mod)

    i = 0
    while i < common:
        if original_data[i] == modified_data[i]:
            i += 1
            continue
        run_start = i
        while i < common and original_data[i] != modified_data[i]:
            i += 1
        runs.append((run_start, modified_data[run_start:i]))

    if n_mod > n_orig:
        runs.append((n_orig, modified_data[n_orig:]))

    return runs


def _split_runs_by_max_length(runs: list[tuple[int, bytes]], max_length: int) -> list[tuple[int, bytes]]:
    """Split runs that exceed ``max_length`` into multiple records.

    Args:
        runs: Diff runs to split.
        max_length: Maximum bytes allowed per record.

    Returns:
        list[tuple[int, bytes]]: Runs with no record exceeding ``max_length``.

    Raises:
        ValueError: If ``max_length`` is not strictly positive.
    """
    if max_length <= 0:
        msg = "max_length must be positive"
        raise ValueError(msg)
    out: list[tuple[int, bytes]] = []
    for offset, data in runs:
        if len(data) <= max_length:
            out.append((offset, data))
            continue
        cursor = 0
        while cursor < len(data):
            chunk = data[cursor : cursor + max_length]
            out.append((offset + cursor, chunk))
            cursor += max_length
    return out


def export_ips_patch(original_data: bytes, modified_data: bytes) -> bytes:
    """Generate IPS-format patch bytes from a diff of original to modified data.

    Selects IPS or IPS32 automatically based on the modified data length.
    Files whose modified length exceeds ``IPS_MAX_OFFSET`` use the IPS32
    variant with a 4-byte offset field.

    Args:
        original_data: Bytes of the unmodified source.
        modified_data: Bytes of the patched target.

    Returns:
        bytes: Complete IPS or IPS32 patch payload starting with the magic
            and ending with the EOF marker.

    Raises:
        ValueError: If ``modified_data`` is too large for both IPS and
            IPS32, or if a single diff run exceeds the maximum encodable
            offset for the chosen variant.
    """
    target_size = len(modified_data)
    use_ips32 = target_size > IPS_MAX_OFFSET
    if use_ips32 and target_size > IPS32_MAX_OFFSET:
        msg = f"modified data length {target_size} exceeds IPS32 max offset {IPS32_MAX_OFFSET}"
        raise ValueError(msg)

    runs = _diff_runs(original_data, modified_data)
    runs = _split_runs_by_max_length(runs, IPS_MAX_RUN_LENGTH)

    parts: list[bytes] = [IPS32_MAGIC if use_ips32 else IPS_MAGIC]

    for offset, data in runs:
        max_offset = IPS32_MAX_OFFSET if use_ips32 else IPS_MAX_OFFSET
        if offset > max_offset:
            msg = f"diff run offset {offset} exceeds maximum offset {max_offset}"
            raise ValueError(msg)
        if use_ips32:
            parts.append(struct.pack(">I", offset))
        else:
            parts.append(struct.pack(">I", offset)[1:])
        parts.extend((struct.pack(">H", len(data)), data))

    parts.append(IPS32_EOF_MARKER if use_ips32 else IPS_EOF_MARKER)

    payload = b"".join(parts)
    _logger.debug(
        "ips_patch_built",
        ips32=use_ips32,
        record_count=len(runs),
        payload_size=len(payload),
        target_size=target_size,
    )
    return payload


def _validate_ips_header(patch: bytes) -> tuple[bool, int, bytes]:
    """Validate an IPS patch header and return parsing parameters.

    Args:
        patch: Raw IPS patch bytes.

    Returns:
        tuple[bool, int, bytes]: ``(is_ips32, header_size, eof_marker)``.

    Raises:
        ValueError: If ``patch`` is too short or has an unknown magic.
    """
    if len(patch) < IPS_HEADER_SIZE:
        msg = f"IPS patch too short: {len(patch)} bytes"
        raise ValueError(msg)
    magic = patch[:IPS_HEADER_SIZE]
    if magic == IPS_MAGIC:
        return False, IPS_HEADER_SIZE, IPS_EOF_MARKER
    if magic == IPS32_MAGIC:
        return True, IPS_HEADER_SIZE, IPS32_EOF_MARKER
    msg = f"unrecognized IPS magic: 0x{magic.hex()}"
    raise ValueError(msg)


def _read_ips_record(patch: bytes, pos: int, *, ips32: bool) -> tuple[int, int, int] | None:
    """Read a single record header from an IPS patch.

    Args:
        patch: Raw IPS patch bytes.
        pos: Byte position of the next record header.
        ips32: Whether the patch is the IPS32 variant.

    Returns:
        tuple[int, int, int] | None: ``(offset, size, new_pos)`` after
            consuming the offset and size fields, or ``None`` if the patch
            ends mid-record.
    """
    offset_size = IPS32_OFFSET_SIZE if ips32 else IPS_OFFSET_SIZE
    header_total = offset_size + IPS_LENGTH_FIELD_SIZE
    if pos + header_total > len(patch):
        return None
    if ips32:
        offset = struct.unpack(">I", patch[pos : pos + offset_size])[0]
    else:
        offset = struct.unpack(">I", b"\x00" + patch[pos : pos + offset_size])[0]
    size_pos = pos + offset_size
    size = struct.unpack(">H", patch[size_pos : size_pos + IPS_LENGTH_FIELD_SIZE])[0]
    return offset, size, pos + header_total


def import_ips_patch(original_data: bytes, patch: bytes) -> bytes:
    """Apply an IPS or IPS32 patch to ``original_data`` and return the result.

    Validates the magic header before parsing records. Supports the IPS
    run-length encoding extension where a record with ``size == 0`` is
    followed by a 2-byte run length and a single fill byte that is
    expanded ``run_length`` times at ``offset``.

    Args:
        original_data: Bytes of the unmodified source to patch.
        patch: Raw IPS/IPS32 patch payload.

    Returns:
        bytes: ``original_data`` with all patch records applied.

    Raises:
        ValueError: If the patch header is invalid or a record is
            truncated.
    """
    ips32, header_size, eof_marker = _validate_ips_header(patch)
    eof_len = len(eof_marker)
    pos = header_size

    target = bytearray(original_data)
    records_applied = 0

    while pos < len(patch):
        if patch[pos : pos + eof_len] == eof_marker:
            break
        record = _read_ips_record(patch, pos, ips32=ips32)
        if record is None:
            msg = "truncated IPS record header"
            raise ValueError(msg)
        offset, size, pos = record

        if size == 0:
            if pos + 3 > len(patch):
                msg = "truncated IPS RLE record"
                raise ValueError(msg)
            run_length = struct.unpack(">H", patch[pos : pos + IPS_LENGTH_FIELD_SIZE])[0]
            fill_value = patch[pos + IPS_LENGTH_FIELD_SIZE]
            pos += IPS_LENGTH_FIELD_SIZE + 1
            patch_data = bytes([fill_value]) * run_length
        else:
            if pos + size > len(patch):
                msg = "truncated IPS data record"
                raise ValueError(msg)
            patch_data = patch[pos : pos + size]
            pos += size

        end_offset = offset + len(patch_data)
        if end_offset > len(target):
            target.extend(b"\x00" * (end_offset - len(target)))
        target[offset:end_offset] = patch_data
        records_applied += 1

    _logger.debug(
        "ips_patch_applied",
        ips32=ips32,
        records=records_applied,
        target_size=len(target),
    )
    return bytes(target)
