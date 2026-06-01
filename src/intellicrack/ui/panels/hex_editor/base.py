# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared constants, utility functions, and dynamic imports for the hex editor package."""

from __future__ import annotations

import contextlib
import hashlib
import mmap
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator


_CRC_STREAM_DEFAULT_CHUNK: Final[int] = 1 << 20


__all__ = [
    "DataReaderCls",
    "HexDisassembler_cls",
    "HexDocumentEvent_cls",
    "HexPatInterpreter_cls",
    "PatternRegistryCls",
    "YaraScanner_cls",
    "get_all_transform_nodes_fn",
    "pefile",
]

_logger = get_logger(__name__)

hexpat_mod: Any = None
hexpat_available: bool = False

try:
    import importlib as _importlib

    hexpat_mod = _importlib.import_module("intellicrack.core.hexpat_compiler")
    hexpat_available = True
except ImportError:
    _logger.debug("hexpat_compiler_import_unavailable")

HexPatInterpreter_cls: Any = None
PatternRegistryCls: Any = None
DataReaderCls: Any = None
hexpat_interpreter_available: bool = False
try:
    from intellicrack.core.hexpat import (
        HexPatInterpreter as HexPatInterpreter_cls,
        PatternRegistry as PatternRegistryCls,
    )
    from intellicrack.core.hexpat.data_reader import DataReader as DataReaderCls

    hexpat_interpreter_available = True
except ImportError:
    _logger.debug("hexpat_interpreter_import_unavailable")

try:
    import pefile

    pefile_available: bool = True
except ImportError:
    pefile = None
    pefile_available = False
    _logger.debug("pefile_import_unavailable")

_xxhash_mod: Any = None
_xxhash_available: bool = False
try:
    import xxhash as _xxhash_import

    _xxhash_mod = _xxhash_import
    _xxhash_available = True
except ImportError:
    _logger.debug("xxhash_import_unavailable")

hexcore: Any = None
hexcore_available: bool = False

try:
    import intellicrack_hexcore as _hexcore_mod

    hexcore = _hexcore_mod
    hexcore_available = True
except ImportError:
    _logger.debug("hexcore_import_unavailable")

HexDocumentEvent_cls: Any = None
hex_state_available: bool = False
try:
    from intellicrack.bridges.hex_state import HexDocumentEvent as HexDocumentEvent_cls

    hex_state_available = True
except ImportError:
    _logger.debug("hex_state_import_unavailable")

HexDisassembler_cls: Any = None
disassembler_available: bool = False
try:
    from intellicrack.core.disassembler import HexDisassembler as HexDisassembler_cls

    disassembler_available = True
except ImportError:
    _logger.debug("disassembler_import_unavailable")

YaraScanner_cls: Any = None
yara_scanner_available: bool = False
try:
    from intellicrack.core.yara_scanner import YaraScanner as YaraScanner_cls

    yara_scanner_available = True
except ImportError:
    _logger.debug("yara_scanner_import_unavailable")

get_all_transform_nodes_fn: Any = None
transform_pipeline_available: bool = False
try:
    from intellicrack.core.transform_pipeline import (
        get_all_transform_nodes as get_all_transform_nodes_fn,
    )

    transform_pipeline_available = True
except ImportError:
    _logger.debug("transform_pipeline_import_unavailable")


KB = 1024
MB = KB**2
GB = MB * KB
PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E

ENTROPY_LOW_THRESHOLD: float = 3.5
ENTROPY_HIGH_THRESHOLD: float = 6.5
ENTROPY_MAX: float = 8.0
BYTE_VALUES_COUNT: int = 256
ENTROPY_BLOCK_SIZE: int = 4096
PREVIEW_BYTES: int = 256
CURSOR_CONTEXT_BYTES: int = 128
HEX_ROW_WIDTH: int = 16
MAX_SEARCH_RESULTS: int = 100
MAX_INSN_BYTES: int = 15
DESCRIPTION_TRUNCATE_LEN: int = 80
SPLITTER_MAIN_RATIO: float = 0.65
SPLITTER_PATTERN_RATIO: float = 0.35
BYTE_TYPE_DIST_MIN_LEN: int = 4
IPS_OFFSET_SIZE: int = 3
IPS32_OFFSET_SIZE: int = 4
IPS_LENGTH_FIELD_SIZE: int = 2
IPS_HEADER_SIZE: int = 5
YARA_MATCH_DISPLAY_BYTES: int = 32
DEFAULT_DISASM_COUNT: int = 50


def format_size(size: int) -> str:
    """Format a byte size as a human-readable string.

    Args:
        size: Size in bytes.

    Returns:
        str: Formatted size string (e.g. "1.5 MB").
    """
    if size < KB:
        return f"{size} B"
    if size < MB:
        return f"{size / KB:.1f} KB"
    return f"{size / MB:.1f} MB" if size < GB else f"{size / GB:.2f} GB"


def _reflect_bits(value: int, width: int) -> int:
    """Reflect (reverse) the bit order of an integer.

    Args:
        value: Integer value to reflect.
        width: Bit width of the value.

    Returns:
        int: Bit-reversed integer.
    """
    result = 0
    for _ in range(width):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def compute_custom_crc(
    data: bytes,
    width: int,
    poly: int,
    init: int,
    *,
    ref_in: bool,
    ref_out: bool,
    xor_out: int,
) -> int:
    """Compute a parametric CRC checksum.

    Args:
        data: Input bytes.
        width: CRC bit width (8, 16, 32, or 64).
        poly: Generator polynomial.
        init: Initial CRC value.
        ref_in: Reflect each input byte before processing.
        ref_out: Reflect the final CRC value before XOR-out.
        xor_out: Value to XOR with the final CRC.

    Returns:
        int: Computed CRC value.
    """
    mask = (1 << width) - 1
    msb_mask = 1 << (width - 1)
    top_bit_shift = width - 1
    crc = init & mask
    for byte in data:
        b = _reflect_bits(byte, 8) if ref_in else byte
        for i in range(7, -1, -1):
            bit = (b >> i) & 1
            crc ^= bit << top_bit_shift
            crc = ((crc << 1) ^ poly) & mask if crc & msb_mask else (crc << 1) & mask
    if ref_out:
        crc = _reflect_bits(crc, width)
    return (crc ^ xor_out) & mask


def _iter_file_chunks_for_crc(path: Path, chunk_size: int) -> Iterator[bytes]:
    """Yield ``chunk_size`` byte slices from ``path`` via :class:`mmap.mmap`.

    Args:
        path: Path to a regular file the caller will stream.
        chunk_size: Bytes per slice handed to the consumer.

    Yields:
        bytes: Successive ``chunk_size``-sized slices of the file.
    """
    with path.open("rb") as fh:
        size = path.stat().st_size
        if size == 0:
            return
        with contextlib.closing(mmap.mmap(fh.fileno(), length=0, access=mmap.ACCESS_READ)) as mm:
            offset = 0
            while offset < size:
                end = min(offset + chunk_size, size)
                yield bytes(mm[offset:end])
                offset = end


def _iter_document_chunks_for_crc(
    document: object,
    length: int,
    chunk_size: int,
) -> Iterator[bytes]:
    """Yield ``chunk_size`` byte slices from a hexcore-style document.

    Normalises the document's ``read`` return type so the CRC inner
    loop always sees ``bytes``.

    Args:
        document: Hexcore-style document exposing ``read(offset, length)``.
        length: Total number of bytes to stream.
        chunk_size: Bytes per slice handed to the consumer.

    Yields:
        bytes: Successive ``chunk_size``-sized slices of the document.

    Raises:
        TypeError: If ``document`` exposes no callable ``read`` attribute,
            or if ``document.read`` returns an unsupported type.
    """
    read_fn = cast("Callable[[int, int], object]", getattr(document, "read", None))
    if not callable(read_fn):
        msg = "document does not expose a callable read(offset, length)"
        raise TypeError(msg)
    offset = 0
    while offset < length:
        n = min(chunk_size, length - offset)
        raw: object = read_fn(offset, n)
        if isinstance(raw, bytes):
            yield raw
        elif isinstance(raw, bytearray):
            yield bytes(raw)
        elif isinstance(raw, list):
            yield bytes(cast("list[int]", raw))
        else:
            msg = f"document.read returned unexpected type: {type(raw).__name__}"
            raise TypeError(msg)
        offset += n


def _build_crc_table(width: int, poly: int) -> tuple[int, ...]:
    """Build a 256-entry table for byte-at-a-time CRC processing.

    Args:
        width: CRC bit width.
        poly: Generator polynomial.

    Returns:
        tuple[int, ...]: 256-entry lookup table.
    """
    mask = (1 << width) - 1
    msb_mask = 1 << (width - 1)
    shift = width - 8
    table: list[int] = []
    for byte in range(256):
        crc = (byte << shift) & mask
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & mask if crc & msb_mask else (crc << 1) & mask
        table.append(crc)
    return tuple(table)


_ZLIB_CRC32_POLY: Final[int] = 0x04C11DB7
_ZLIB_CRC32_INIT: Final[int] = 0xFFFFFFFF
_ZLIB_CRC32_XOR_OUT: Final[int] = 0xFFFFFFFF
_CRC32_WIDTH: Final[int] = 32


def _is_zlib_crc32(width: int, poly: int, init: int, *, ref_in: bool, ref_out: bool, xor_out: int) -> bool:
    """Check whether the parameters match the standard zlib/PKZIP CRC-32.

    Args:
        width: CRC bit width.
        poly: Generator polynomial.
        init: Initial CRC value.
        ref_in: Reflect input flag.
        ref_out: Reflect output flag.
        xor_out: Final XOR mask.

    Returns:
        bool: True if every parameter matches the standard CRC-32 contract.
    """
    return (
        width == _CRC32_WIDTH
        and poly == _ZLIB_CRC32_POLY
        and init == _ZLIB_CRC32_INIT
        and ref_in
        and ref_out
        and xor_out == _ZLIB_CRC32_XOR_OUT
    )


def _crc_over_chunks(
    chunks: Iterable[bytes],
    width: int,
    poly: int,
    init: int,
    *,
    ref_in: bool,
    ref_out: bool,
    xor_out: int,
) -> int:
    """Run a table-driven CRC over a chunk iterator.

    Algebraically identical to the bit-serial reference but processes
    one byte per iteration via a precomputed 256-entry table — orders
    of magnitude faster for multi-megabyte streams while keeping memory
    usage bounded. The standard zlib/PKZIP CRC-32 parameter set
    short-circuits to :func:`zlib.crc32` so files in the hundreds of
    megabytes complete in under a second.

    Args:
        chunks: Iterable producing the message bytes one chunk at a time.
        width: CRC bit width.
        poly: Generator polynomial.
        init: Initial CRC value.
        ref_in: Reflect each input byte before processing.
        ref_out: Reflect the final CRC value before XOR-out.
        xor_out: Value to XOR with the final CRC.

    Returns:
        int: Computed CRC value.
    """
    if _is_zlib_crc32(width, poly, init, ref_in=ref_in, ref_out=ref_out, xor_out=xor_out):
        crc = 0
        for chunk in chunks:
            if chunk:
                crc = zlib.crc32(chunk, crc)
        return crc & 0xFFFFFFFF

    mask = (1 << width) - 1
    table = _build_crc_table(width, poly)
    crc = init & mask
    shift = width - 8
    for chunk in chunks:
        if not chunk:
            continue
        for byte in chunk:
            idx = ((_reflect_bits(byte, 8) ^ (crc >> shift)) & 0xFF) if ref_in else ((byte ^ (crc >> shift)) & 0xFF)
            crc = ((crc << 8) ^ table[idx]) & mask
    if ref_out:
        crc = _reflect_bits(crc, width)
    return (crc ^ xor_out) & mask


def compute_streaming_custom_crc(
    file_path: str | None,
    document: object,
    width: int,
    poly: int,
    init: int,
    *,
    ref_in: bool,
    ref_out: bool,
    xor_out: int,
    chunk_size: int = _CRC_STREAM_DEFAULT_CHUNK,
) -> int:
    """Compute a parametric CRC across a streamed document, off the UI thread.

    Identical algebraic result to :func:`compute_custom_crc` but never
    requires the full message to be present in memory simultaneously,
    which keeps the calling thread under a bounded memory budget when
    the document is many tens or hundreds of megabytes. When
    ``file_path`` is provided and points at a readable regular file the
    caller streams via :class:`mmap.mmap` and never copies file pages
    into Python heap memory; otherwise the caller streams via
    ``document.read`` in ``chunk_size`` chunks.

    Args:
        file_path: Path to the file backing the document, or ``None``
            to force the document-based path.
        document: Hexcore-style document exposing
            ``read(offset, length)``. Used when ``file_path`` is ``None``.
        width: CRC bit width (8, 16, 32, or 64).
        poly: Generator polynomial.
        init: Initial CRC value.
        ref_in: Reflect each input byte before processing.
        ref_out: Reflect the final CRC value before XOR-out.
        xor_out: Value to XOR with the final CRC.
        chunk_size: Bytes per chunk for the document path.

    Returns:
        int: Computed CRC value.
    """
    if file_path is not None:
        chunks: Iterable[bytes] = _iter_file_chunks_for_crc(Path(file_path), chunk_size)
    else:
        length = _length_of(document)
        chunks = _iter_document_chunks_for_crc(document, length, chunk_size)
    return _crc_over_chunks(
        chunks,
        width,
        poly,
        init,
        ref_in=ref_in,
        ref_out=ref_out,
        xor_out=xor_out,
    )


def _length_of(document: object) -> int:
    """Return ``document.length()`` as an integer, raising ``TypeError`` otherwise.

    Args:
        document: Hexcore-style document exposing ``length()``.

    Returns:
        int: Document length in bytes.

    Raises:
        TypeError: If ``document`` exposes no callable ``length`` attribute,
            or if it returns a non-integer value.
    """
    length_fn = cast("Callable[[], object]", getattr(document, "length", None))
    if not callable(length_fn):
        msg = "document does not expose a callable length()"
        raise TypeError(msg)
    raw: object = length_fn()
    if not isinstance(raw, int):
        msg = f"document.length() returned unexpected type: {type(raw).__name__}"
        raise TypeError(msg)
    return raw


def _compute_hash_stdlib(algo: str, data: bytes) -> str | None:
    """Compute a hash using stdlib hashlib algorithms.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex digest, or None if the algorithm is not handled here.
    """
    stdlib_map: dict[str, str] = {
        "MD5": "md5",
        "SHA-1": "sha1",
    }
    if algo in stdlib_map:
        return hashlib.new(stdlib_map[algo], data).hexdigest()
    attr_map: dict[str, Any] = {
        "SHA-224": hashlib.sha224,
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "SHA3-256": hashlib.sha3_256,
        "SHA3-512": hashlib.sha3_512,
    }
    if algo in attr_map:
        return attr_map[algo](data).hexdigest()
    if algo == "Blake2b-256":
        return hashlib.blake2b(data, digest_size=32).hexdigest()
    if algo == "Blake2s-256":
        return hashlib.blake2s(data, digest_size=32).hexdigest()
    return None


def _compute_hash_xxhash(algo: str, data: bytes) -> str | None:
    """Compute a hash using the xxhash library.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex digest, or an error string, or None if not an xxhash algo.
    """
    if algo not in {"XXHash32", "XXHash64", "XXH3-64"}:
        return None
    if not _xxhash_available or _xxhash_mod is None:
        return "Error: xxhash not installed"
    if algo == "XXHash32":
        return str(_xxhash_mod.xxh32(data).hexdigest())
    if algo == "XXHash64":
        return str(_xxhash_mod.xxh64(data).hexdigest())
    return str(_xxhash_mod.xxh3_64(data).hexdigest())


def _compute_hash_siphash(algo: str, data: bytes) -> str | None:
    """Compute a SipHash digest.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex digest, or an error string, or None if not a SipHash algo.
    """
    sip_attr_map: dict[str, str] = {
        "SipHash64": "siphash13",
        "SipHash128": "siphash24",
    }
    if algo not in sip_attr_map:
        return None
    sip_fn = getattr(hashlib, sip_attr_map[algo], None)
    if sip_fn is None:
        return "Error: SipHash not available (Python 3.12+ required)"
    return sip_fn(b"\x00" * 16, data).hex()


def _compute_hash_checksums(algo: str, data: bytes) -> str | None:
    """Compute CRC or Adler checksum.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex checksum string, or None if not a checksum algo.
    """
    if algo == "Adler32":
        return f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"
    if algo == "CRC-8":
        crc = compute_custom_crc(data, 8, 0x07, 0x00, ref_in=False, ref_out=False, xor_out=0x00)
        return f"{crc:02x}"
    if algo == "CRC-16":
        crc = compute_custom_crc(data, 16, 0x8005, 0x0000, ref_in=True, ref_out=True, xor_out=0x0000)
        return f"{crc:04x}"
    if algo == "CRC-32":
        return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    if algo == "CRC-64":
        crc = compute_custom_crc(
            data,
            64,
            0x42F0E1EBA9EA3693,
            0xFFFFFFFFFFFFFFFF,
            ref_in=False,
            ref_out=False,
            xor_out=0xFFFFFFFFFFFFFFFF,
        )
        return f"{crc:016x}"
    return None


def _compute_hash_fnv(algo: str, data: bytes) -> str | None:
    """Compute an FNV hash.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex hash string, or None if not an FNV algo.
    """
    fnv32_prime = 16777619
    fnv64_prime = 1099511628211
    fnv32_offset = 2166136261
    fnv64_offset = 14695981039346656037
    fnv32_mask = 0xFFFFFFFF
    fnv64_mask = 0xFFFFFFFFFFFFFFFF

    if algo == "FNV1-32":
        h = fnv32_offset
        for b in data:
            h = ((h * fnv32_prime) ^ b) & fnv32_mask
        return f"{h:08x}"
    if algo == "FNV1-64":
        h = fnv64_offset
        for b in data:
            h = ((h * fnv64_prime) ^ b) & fnv64_mask
        return f"{h:016x}"
    if algo == "FNV1a-32":
        h = fnv32_offset
        for b in data:
            h = ((h ^ b) * fnv32_prime) & fnv32_mask
        return f"{h:08x}"
    if algo == "FNV1a-64":
        h = fnv64_offset
        for b in data:
            h = ((h ^ b) * fnv64_prime) & fnv64_mask
        return f"{h:016x}"
    return None


def _compute_hash_impl(algo: str, data: bytes) -> str | None:
    """Dispatch ``algo`` across the supported hash backends.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex-encoded hash result, or ``None`` when no backend
            recognized ``algo``.
    """
    result = _compute_hash_stdlib(algo, data)
    if result is not None:
        return result
    result = _compute_hash_xxhash(algo, data)
    if result is not None:
        return result
    result = _compute_hash_siphash(algo, data)
    if result is not None:
        return result
    result = _compute_hash_checksums(algo, data)
    if result is not None:
        return result
    return _compute_hash_fnv(algo, data)


def compute_hash(algo: str, data: bytes) -> str:
    """Compute a hash or checksum of data using the specified algorithm.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str: Hex-encoded hash result, or an error message prefixed with "Error:".
    """
    try:
        result = _compute_hash_impl(algo, data)
    except (ValueError, TypeError, OSError, RuntimeError, ImportError) as exc:
        _logger.exception("compute_hash_failed", algo=algo)
        return f"Error: {exc}"
    else:
        return result if result is not None else f"Error: unknown algorithm {algo}"


HASH_ALGORITHMS: list[str] = [
    "MD5",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
    "SHA3-512",
    "Blake2b-256",
    "Blake2s-256",
    "XXHash32",
    "XXHash64",
    "XXH3-64",
    "SipHash64",
    "SipHash128",
    "Adler32",
    "CRC-8",
    "CRC-16",
    "CRC-32",
    "CRC-64",
    "FNV1-32",
    "FNV1-64",
    "FNV1a-32",
    "FNV1a-64",
]

ENCODING_ENTRIES: list[str] = [
    "UTF-8",
    "ASCII",
    "UTF-16LE",
    "UTF-16BE",
    "--- Western ---",
    "Windows-1252",
    "ISO-8859-1",
    "ISO-8859-15",
    "--- Central European ---",
    "Windows-1250",
    "ISO-8859-2",
    "--- Cyrillic ---",
    "Windows-1251",
    "KOI8-R",
    "KOI8-U",
    "ISO-8859-5",
    "--- Greek ---",
    "Windows-1253",
    "ISO-8859-7",
    "--- Turkish ---",
    "Windows-1254",
    "--- Japanese ---",
    "Shift-JIS",
    "EUC-JP",
    "ISO-2022-JP",
    "--- Chinese ---",
    "GBK",
    "GB18030",
    "Big5",
    "--- Korean ---",
    "EUC-KR",
    "--- Other ---",
    "EBCDIC",
]
