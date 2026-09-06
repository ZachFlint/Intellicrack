# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""One invocation recipe for every callable the engine exposes.

:data:`RECIPES` maps each name in :func:`~hexbench.catalog.operation_names` to a
callable that produces a complete, valid argument set for it. That mapping is
the coverage gate's teeth: the day a ninety-first method lands in the Rust crate
:func:`coverage_gap` starts reporting ``no invocation recipe for: [...]`` and the
suite fails until somebody decides how the new operation should be driven. The
table is indivisible for that reason, and lives apart from the fixtures that
consume it.

Every recipe genuinely invokes its operation. Nothing here is skipped for being
awkward to arrange, so the recipes that depend on their environment instead
declare which failures still count as a documented outcome:
:attr:`Recipe.tolerated` names the :class:`~hexbench.dispatch.DispatchError`
kinds a caller may accept, and :attr:`Recipe.note` says why. Only the two
process-memory operations carry any tolerance at all, and both of them run
against this very process rather than hunting for a victim.

Three payloads are derived from the engine rather than transcribed into this
file. A BPS patch, a UPS patch and a custom template definition are all formats
whose exact bytes belong to the Rust crate; restating them by hand would produce
a test that agrees with a guess instead of with the engine, so each is built by
asking the engine to export one. The IPS patch is the exception and is
constructed here byte by byte, because IPS is a fixed, trivially specified
format and an independently built patch proves the importer reads something it
did not write.
"""

from __future__ import annotations

import ctypes
import json
import os
import struct
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

from intellicrack_hexcore import HexDocument

from hexbench.catalog import operation_names


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from hexbench.codec import JsonValue


__all__ = [
    "BLOCK_SIZE",
    "BOOKMARK_COLOR",
    "BOOKMARK_LABEL",
    "BUILTIN_TEMPLATE",
    "CHUNK_SIZE_HINT",
    "CUSTOM_TEMPLATE_NAME",
    "FILL_PATTERN",
    "FLOAT_SIZE",
    "FLOAT_VALUE",
    "HASH_ALGORITHM",
    "INSERTED_BYTES",
    "IPS_PATCH",
    "IPS_PAYLOAD",
    "IPS_TARGET_OFFSET",
    "MAX_RESULTS",
    "MEMORY_BUDGET_HINT",
    "NEEDLE",
    "NUMERIC_SIZE",
    "NUMERIC_VALUE",
    "PROCESS_PROBE_MARKER",
    "RECIPES",
    "REPLACEMENT",
    "SAMPLE",
    "SAMPLE_LENGTH",
    "SAMPLE_VARIANT",
    "SEARCH_REGEX",
    "TEXT_ENCODING",
    "TRANSFORM_KEY",
    "TRANSFORM_LENGTH",
    "TRANSFORM_NAME",
    "TRANSFORM_OFFSET",
    "VARIANT_LENGTH",
    "VARIANT_OFFSET",
    "VA_BASE",
    "VA_LENGTH",
    "WIDE_ENCODING",
    "WIDE_TEXT",
    "WRITTEN_BYTES",
    "Recipe",
    "RecipeBuilder",
    "RecipeContext",
    "RecipeError",
    "SampleLayout",
    "Target",
    "bps_patch",
    "coverage_gap",
    "custom_template_json",
    "missing_recipes",
    "needle_hex",
    "process_probe_address",
    "process_probe_size",
    "recipe_for",
    "unknown_recipes",
    "ups_patch",
]


SAMPLE_LENGTH: Final = 512
"""Size in bytes of the synthetic document every non-PE recipe runs against."""

NEEDLE: Final[bytes] = b"quick"
"""Byte string planted once in the sample, for the byte, hex and text searches."""

REPLACEMENT: Final[bytes] = b"brisk"
"""Same-length stand-in for :data:`NEEDLE` used by ``replace_bytes``."""

NUMERIC_VALUE: Final = 42
"""Unsigned little-endian integer planted once in the sample."""

NUMERIC_SIZE: Final = 4
"""Width in bytes of :data:`NUMERIC_VALUE` as it appears in the sample."""

FLOAT_VALUE: Final = 1.5
"""Little-endian binary32 value planted once in the sample."""

FLOAT_SIZE: Final = 4
"""Width in bytes of :data:`FLOAT_VALUE` as it appears in the sample."""

WIDE_TEXT: Final = "WIDECHARS"
"""String planted in the sample as UTF-16LE, for the encoded text search."""

WIDE_ENCODING: Final = "utf-16le"
"""Engine encoding name :data:`WIDE_TEXT` is planted with."""

TEXT_ENCODING: Final = "utf-8"
"""Engine encoding name used wherever a recipe needs a plain text codec."""

SEARCH_REGEX: Final = "qu[a-z]+k"
"""Pattern that matches :data:`NEEDLE` and nothing else in the sample."""

HASH_ALGORITHM: Final = "sha256"
"""Digest algorithm used by the hashing recipes."""

MAX_RESULTS: Final = 64
"""Result cap handed to every search recipe."""

BLOCK_SIZE: Final = 64
"""Block size for the entropy map and the content classification."""

VA_BASE: Final = 0x400000
"""Virtual address the addressing recipes map the start of the document to."""

VA_LENGTH: Final = 256
"""Length in bytes of the virtual address mapping the recipes install."""

BOOKMARK_LABEL: Final = "hexbench sample"
"""Label carried by every bookmark the recipes create."""

BOOKMARK_COLOR: Final = "#ff8800"
"""Colour carried by every bookmark the recipes create."""

BUILTIN_TEMPLATE: Final = "IMAGE_DOS_HEADER"
"""Builtin template the template recipes apply and export."""

CUSTOM_TEMPLATE_NAME: Final = "HEXBENCH_TEST_TEMPLATE"
"""Name under which :func:`custom_template_json` registers its definition."""

TRANSFORM_NAME: Final = "xor_repeating"
"""Transform the ``transform_data`` recipe runs."""

TRANSFORM_KEY: Final[bytes] = b"\x5a"
"""Raw key bytes handed to :data:`TRANSFORM_NAME`."""

TRANSFORM_OFFSET: Final = 0
"""Offset the transform recipe starts at."""

TRANSFORM_LENGTH: Final = 16
"""Number of bytes the transform recipe covers."""

INSERTED_BYTES: Final[bytes] = b"\x00\x11\x22\x33"
"""Payload for the ``insert_bytes`` recipe."""

WRITTEN_BYTES: Final[bytes] = b"\xde\xad\xbe\xef"
"""Payload for the ``write_bytes`` recipe."""

FILL_PATTERN: Final[bytes] = b"\xcc"
"""Pattern for the ``fill_block`` recipe."""

CHUNK_SIZE_HINT: Final = 1 << 16
"""Value the ``set_chunk_size_hint`` recipe installs."""

MEMORY_BUDGET_HINT: Final = 1 << 26
"""Value the ``set_memory_budget_hint`` recipe installs."""

VARIANT_OFFSET: Final = 200
"""Offset at which :data:`SAMPLE_VARIANT` diverges from the sample."""

VARIANT_LENGTH: Final = 8
"""Number of bytes by which :data:`SAMPLE_VARIANT` diverges from the sample."""

IPS_TARGET_OFFSET: Final = 0x10
"""Offset the hand-built IPS patch writes to."""

IPS_PAYLOAD: Final[bytes] = b"\xaa\xbb"
"""Bytes the hand-built IPS patch writes."""

PROCESS_PROBE_MARKER: Final[bytes] = b"HEXBENCH-PROCESS-MEMORY-PROBE"
"""Marker held in this process's own memory for the process-memory recipes."""

_SAMPLE_HEADER: Final[bytes] = b"HEXBENCH SAMPLE DOCUMENT\x00"
_SAMPLE_SENTENCE: Final[bytes] = b"the quick brown fox jumps over the lazy dog\x00"
_NUMERIC_FORMAT: Final = "<I"
_FLOAT_FORMAT: Final = "<f"
_WIDE_TERMINATOR: Final[bytes] = b"\x00\x00"
_BYTE_VALUES: Final = 256
_FILLER_STRIDE: Final = 7
_BYTE_MASK: Final = 0xFF
_VARIANT_FILLER: Final[bytes] = b"\xff"

_IPS_MAGIC: Final[bytes] = b"PATCH"
_IPS_TERMINATOR: Final[bytes] = b"EOF"
_IPS_OFFSET_WIDTH: Final = 3
_IPS_LENGTH_WIDTH: Final = 2
_BIG_ENDIAN: Final = "big"

_DERIVED_EDIT_OFFSET: Final = 16
_DERIVED_EDIT: Final[bytes] = b"\xde\xad\xbe\xef"

_TEMPLATE_NAME_FIELD: Final = "name"
_TEMPLATE_FIELDS_FIELD: Final = "fields"

_CRC_POLY: Final = 0x04C11DB7
_CRC_INIT: Final = 0xFFFFFFFF
_CRC_WIDTH: Final = 32
_CRC_XOROUT: Final = 0xFFFFFFFF

_HASH_RANGE_END: Final = 64
_READ_LENGTH: Final = 16
_DECODE_LENGTH: Final = 8
_MIN_STRING_LENGTH: Final = 4
_BLOCK_LENGTH: Final = 16
_BLOCK_DESTINATION: Final = 256
_SWAP_LENGTH: Final = 8
_SWAP_SECOND_OFFSET: Final = 64
_DELETE_OFFSET: Final = 256
_DELETE_LENGTH: Final = 16
_BOOKMARK_LENGTH: Final = 4
_SECOND_BOOKMARK_OFFSET: Final = 8
_FIRST_INDEX: Final = 0
_ORIGIN: Final = 0
_HIGH_BIT_INDEX: Final = 7
_ALIGNMENT: Final = 1
_FLOAT_TOLERANCE: Final = 0.001
_RANGE_MARGIN: Final = 2

_SAMPLE_FILE_NAME: Final = "recipe-sample.bin"
_VARIANT_FILE_NAME: Final = "recipe-variant.bin"
_SAVE_FILE_NAME: Final = "recipe-saved.bin"
_SAVE_AS_FILE_NAME: Final = "recipe-saved-as.bin"

_TOLERATE_RUNTIME: Final[frozenset[str]] = frozenset({"runtime"})
_NO_TOLERANCE: Final[frozenset[str]] = frozenset()

_FRESH_DOCUMENT_NOTE: Final = "Returns the not-found answer on a freshly opened document; that is the documented outcome."
_PROCESS_MEMORY_NOTE: Final = (
    "Runs against this process, so it needs no external victim. A hardened host can still refuse the handle, "
    "which surfaces as a runtime failure rather than a skip."
)


class RecipeError(LookupError):
    """Raised when a recipe is requested or built for something that has none."""


class Target(Enum):
    """Which open document a recipe's operation should be invoked against."""

    NONE = "none"
    """Needs no open document: a static, factory or module-level operation."""

    SAMPLE = "sample"
    """The synthetic in-memory document built from :data:`SAMPLE`."""

    EXECUTABLE = "executable"
    """A document opened over a copy of a genuine Windows PE image."""


@dataclass(frozen=True, slots=True)
class SampleLayout:
    """The synthetic document, together with where each planted value sits.

    Recipes and the assertions that check them both read their offsets from
    here, so neither has to restate a number the builder chose.

    Attributes:
        data: The complete document contents.
        needle_offset: Offset of the single occurrence of :data:`NEEDLE`.
        numeric_offset: Offset of :data:`NUMERIC_VALUE` as a little-endian
            unsigned integer of :data:`NUMERIC_SIZE` bytes.
        float_offset: Offset of :data:`FLOAT_VALUE` as a little-endian binary32.
        wide_offset: Offset of :data:`WIDE_TEXT` encoded as UTF-16LE.
    """

    data: bytes
    needle_offset: int
    numeric_offset: int
    float_offset: int
    wide_offset: int


def _build_sample() -> SampleLayout:
    """Assemble the synthetic document and record where each value landed.

    The content is chosen so one document satisfies every read-only recipe at
    once: printable prose for the string extractor and the text searches, a
    planted integer and float for the numeric searches, a UTF-16LE run for the
    encoded search, and a full sweep of all 256 byte values so the statistical
    operations have something other than a flat distribution to report.

    Returns:
        SampleLayout: The document and the offsets of its planted values.
    """
    body = bytearray()
    body += _SAMPLE_HEADER
    needle_offset = len(body) + _SAMPLE_SENTENCE.index(NEEDLE)
    body += _SAMPLE_SENTENCE
    numeric_offset = len(body)
    body += struct.pack(_NUMERIC_FORMAT, NUMERIC_VALUE)
    float_offset = len(body)
    body += struct.pack(_FLOAT_FORMAT, FLOAT_VALUE)
    wide_offset = len(body)
    body += WIDE_TEXT.encode(WIDE_ENCODING) + _WIDE_TERMINATOR
    body += bytes(range(_BYTE_VALUES))
    while len(body) < SAMPLE_LENGTH:
        body.append((len(body) * _FILLER_STRIDE) & _BYTE_MASK)
    return SampleLayout(
        data=bytes(body[:SAMPLE_LENGTH]),
        needle_offset=needle_offset,
        numeric_offset=numeric_offset,
        float_offset=float_offset,
        wide_offset=wide_offset,
    )


SAMPLE: Final[SampleLayout] = _build_sample()
"""The synthetic document every :attr:`Target.SAMPLE` recipe runs against."""

SAMPLE_VARIANT: Final[bytes] = (
    SAMPLE.data[:VARIANT_OFFSET] + _VARIANT_FILLER * VARIANT_LENGTH + SAMPLE.data[VARIANT_OFFSET + VARIANT_LENGTH :]
)
"""A copy of the sample differing from it in exactly :data:`VARIANT_LENGTH` bytes."""

_PROCESS_PROBE: Final[ctypes.Array[ctypes.c_char]] = ctypes.create_string_buffer(PROCESS_PROBE_MARKER)


def needle_hex() -> str:
    """Render the planted needle exactly as it sits in the sample.

    Deriving the hexadecimal spelling from the document rather than writing it
    out keeps ``search_hex`` and ``search_bytes`` looking for the same bytes.

    Returns:
        str: Hexadecimal encoding of :data:`NEEDLE`.
    """
    return SAMPLE.data[SAMPLE.needle_offset : SAMPLE.needle_offset + len(NEEDLE)].hex()


def process_probe_address() -> int:
    """Report where this process holds :data:`PROCESS_PROBE_MARKER`.

    The buffer is allocated once at import and referenced for the lifetime of
    the module, so the address stays committed and readable for as long as any
    test can ask for it.

    Returns:
        int: Address of the marker inside this process.
    """
    return ctypes.addressof(_PROCESS_PROBE)


def process_probe_size() -> int:
    """Report how many bytes the process-memory probe covers.

    Returns:
        int: Length of the marker buffer, including its trailing NUL.
    """
    return len(_PROCESS_PROBE.raw)


def _ips_patch() -> bytes:
    """Build an IPS patch by hand, to the published format.

    Returns:
        bytes: A patch writing :data:`IPS_PAYLOAD` at :data:`IPS_TARGET_OFFSET`.
    """
    header = IPS_TARGET_OFFSET.to_bytes(_IPS_OFFSET_WIDTH, _BIG_ENDIAN)
    size = len(IPS_PAYLOAD).to_bytes(_IPS_LENGTH_WIDTH, _BIG_ENDIAN)
    return _IPS_MAGIC + header + size + IPS_PAYLOAD + _IPS_TERMINATOR


IPS_PATCH: Final[bytes] = _ips_patch()
"""A hand-built IPS patch, written without asking the engine what one looks like."""


@lru_cache(maxsize=1)
def _derived_patches() -> tuple[bytes, bytes]:
    """Ask the engine to export a BPS and a UPS patch over a known edit.

    BPS and UPS are the engine's own output formats, so the importers are
    exercised against bytes the exporters produced rather than against a
    hand-rolled guess at the specification.

    Returns:
        tuple[bytes, bytes]: The BPS patch and the UPS patch, in that order.
    """
    document = HexDocument.open_bytes(SAMPLE.data)
    document.write_bytes(_DERIVED_EDIT_OFFSET, _DERIVED_EDIT)
    return document.export_patches_bps(SAMPLE.data), document.export_patches_ups(SAMPLE.data)


def bps_patch() -> bytes:
    """Produce a BPS patch that turns the sample into a known edited form.

    Returns:
        bytes: A BPS patch whose source is :attr:`SampleLayout.data`.
    """
    return _derived_patches()[0]


def ups_patch() -> bytes:
    """Produce a UPS patch that turns the sample into a known edited form.

    Returns:
        bytes: A UPS patch whose source is :attr:`SampleLayout.data`.
    """
    return _derived_patches()[1]


@lru_cache(maxsize=1)
def custom_template_json() -> str:
    """Produce a registrable template definition derived from a builtin one.

    The template schema belongs to the Rust crate. Exporting a builtin
    definition and renaming it yields a document the engine is guaranteed to
    accept without this module having to encode the crate's field grammar.

    Returns:
        str: A template definition named :data:`CUSTOM_TEMPLATE_NAME`.

    Raises:
        RecipeError: If the exported builtin is not an object carrying the name
            and field members the engine documents.
    """
    document = HexDocument.open_bytes(SAMPLE.data)
    decoded: object = json.loads(document.export_template_json(BUILTIN_TEMPLATE))
    if not isinstance(decoded, dict):
        message = f"{BUILTIN_TEMPLATE} exported as {type(decoded).__name__}, not a JSON object"
        raise RecipeError(message)
    definition = cast("dict[str, JsonValue]", decoded)
    missing = [field for field in (_TEMPLATE_NAME_FIELD, _TEMPLATE_FIELDS_FIELD) if field not in definition]
    if missing:
        message = f"{BUILTIN_TEMPLATE} exported without {', '.join(missing)}; the template schema has changed"
        raise RecipeError(message)
    definition[_TEMPLATE_NAME_FIELD] = CUSTOM_TEMPLATE_NAME
    return json.dumps(definition)


@dataclass(frozen=True, slots=True)
class RecipeContext:
    """The environment a recipe draws its arguments from.

    A context is cheap and is meant to be rebuilt for each operation, so every
    recipe sees a document in its opening state rather than one carrying the
    edits of whatever ran before it.

    Attributes:
        sample_handle: Handle of a document opened over :attr:`SampleLayout.data`.
        executable_handle: Handle of a document opened over a copy of a genuine
            PE image.
        executable_path: Filesystem path of that copy.
        scratch: Directory recipes may create files in, deleted with the session.
        pid: Identifier of this process, used by the process-memory recipes.
    """

    sample_handle: str
    executable_handle: str
    executable_path: Path
    scratch: Path
    pid: int

    def handle_for(self, target: Target) -> str | None:
        """Choose which open document a recipe should run against.

        Args:
            target: The document class the recipe declared.

        Returns:
            str | None: The handle to invoke with, or ``None`` for operations
            that act on no open document.
        """
        match target:
            case Target.SAMPLE:
                return self.sample_handle
            case Target.EXECUTABLE:
                return self.executable_handle
            case Target.NONE:
                return None

    def path(self, name: str) -> str:
        """Name a file inside the scratch directory without creating it.

        Args:
            name: Leaf file name.

        Returns:
            str: Absolute path, suitable for an operation that writes a file.
        """
        return str(self.scratch / name)

    def file(self, name: str, data: bytes) -> str:
        """Stage a file in the scratch directory and name it.

        A file already holding exactly these bytes is left alone. That matters
        on Windows: a document opened over a path keeps it memory mapped, and
        rewriting a mapped file fails with ``EINVAL``, so staging the same
        content twice within one context must not touch the disk again.

        Args:
            name: Leaf file name.
            data: Complete contents the file should hold.

        Returns:
            str: Absolute path of the staged file.
        """
        target = self.scratch / name
        if not (target.is_file() and target.read_bytes() == data):
            target.write_bytes(data)
        return str(target)

    def sample_file(self) -> str:
        """Materialise the synthetic document on disk.

        Returns:
            str: Absolute path of a file holding :attr:`SampleLayout.data`.
        """
        return self.file(_SAMPLE_FILE_NAME, SAMPLE.data)

    def variant_file(self) -> str:
        """Materialise the diverging copy of the synthetic document on disk.

        Returns:
            str: Absolute path of a file holding :data:`SAMPLE_VARIANT`.
        """
        return self.file(_VARIANT_FILE_NAME, SAMPLE_VARIANT)


type RecipeBuilder = Callable[[RecipeContext], dict[str, JsonValue]]
"""Signature of the callable a recipe uses to produce its arguments."""


@dataclass(frozen=True, slots=True)
class Recipe:
    """How to invoke one catalogued operation for real.

    Attributes:
        target: Which open document the operation should be invoked against.
        build: Callable producing a complete argument set, keyed by parameter
            name, in the JSON spelling the codec accepts.
        tolerated: Dispatch error kinds that still count as a documented
            outcome, empty for every recipe expected to succeed outright.
        note: Why the recipe behaves as it does, when that is not obvious from
            the arguments alone. Empty when nothing needs saying.
    """

    target: Target
    build: RecipeBuilder
    tolerated: frozenset[str]
    note: str


@dataclass(frozen=True, slots=True)
class _FixedArguments:
    """Argument builder that hands back the same mapping every time.

    Attributes:
        arguments: The argument values, keyed by parameter name.
    """

    arguments: Mapping[str, JsonValue]

    def __call__(self, context: RecipeContext) -> dict[str, JsonValue]:
        """Produce the fixed arguments.

        Args:
            context: Environment the recipe runs in, which fixed arguments
                never consult.

        Returns:
            dict[str, JsonValue]: A fresh copy of the argument mapping.
        """
        del context
        return dict(self.arguments)


def _constant(target: Target, /, **arguments: JsonValue) -> Recipe:
    """Describe an operation whose arguments never vary.

    Args:
        target: Which open document the operation runs against.
        **arguments: Argument values keyed by parameter name.

    Returns:
        Recipe: The described recipe, expected to succeed outright.
    """
    return Recipe(target=target, build=_FixedArguments(dict(arguments)), tolerated=_NO_TOLERANCE, note="")


def _noted(target: Target, note: str, /, **arguments: JsonValue) -> Recipe:
    """Describe an operation whose arguments never vary, with an explanation.

    Args:
        target: Which open document the operation runs against.
        note: Why the recipe behaves as it does.
        **arguments: Argument values keyed by parameter name.

    Returns:
        Recipe: The described recipe, expected to succeed outright.
    """
    return Recipe(target=target, build=_FixedArguments(dict(arguments)), tolerated=_NO_TOLERANCE, note=note)


def _tolerant(target: Target, note: str, tolerated: frozenset[str], /, **arguments: JsonValue) -> Recipe:
    """Describe an operation whose environment may legitimately refuse it.

    Args:
        target: Which open document the operation runs against.
        note: Why the operation may be refused and what that refusal means.
        tolerated: Dispatch error kinds that still count as a documented
            outcome.
        **arguments: Argument values keyed by parameter name.

    Returns:
        Recipe: The described recipe.
    """
    return Recipe(target=target, build=_FixedArguments(dict(arguments)), tolerated=tolerated, note=note)


def _built(target: Target, build: RecipeBuilder, /, note: str = "") -> Recipe:
    """Describe an operation whose arguments depend on the environment.

    Args:
        target: Which open document the operation runs against.
        build: Callable producing the argument set.
        note: Why the recipe behaves as it does, when that needs saying.

    Returns:
        Recipe: The described recipe, expected to succeed outright.
    """
    return Recipe(target=target, build=build, tolerated=_NO_TOLERANCE, note=note)


def _open_arguments(context: RecipeContext) -> dict[str, JsonValue]:
    """Name a real file on disk for the ``open`` factory.

    Args:
        context: Environment the recipe runs in.

    Returns:
        dict[str, JsonValue]: The ``path`` argument.
    """
    return {"path": context.sample_file()}


def _source_path_arguments(context: RecipeContext) -> dict[str, JsonValue]:
    """Name the unmodified original on disk for the path-based patch exports.

    Args:
        context: Environment the recipe runs in.

    Returns:
        dict[str, JsonValue]: The ``source_path`` argument.
    """
    return {"source_path": context.sample_file()}


def _diff_files_arguments(context: RecipeContext) -> dict[str, JsonValue]:
    """Name two real files that differ across a known span.

    Args:
        context: Environment the recipe runs in.

    Returns:
        dict[str, JsonValue]: The ``path_a`` and ``path_b`` arguments.
    """
    return {"path_a": context.sample_file(), "path_b": context.variant_file()}


def _save_arguments(context: RecipeContext) -> dict[str, JsonValue]:
    """Name a writable destination for ``save``.

    Args:
        context: Environment the recipe runs in.

    Returns:
        dict[str, JsonValue]: The ``path`` argument.
    """
    return {"path": context.path(_SAVE_FILE_NAME)}


def _save_as_arguments(context: RecipeContext) -> dict[str, JsonValue]:
    """Name a writable destination for ``save_as``.

    Args:
        context: Environment the recipe runs in.

    Returns:
        dict[str, JsonValue]: The ``path`` argument.
    """
    return {"path": context.path(_SAVE_AS_FILE_NAME)}


def _import_bps_arguments(context: RecipeContext) -> dict[str, JsonValue]:
    """Supply an engine-produced BPS patch and the source it applies to.

    Args:
        context: Environment the recipe runs in.

    Returns:
        dict[str, JsonValue]: The ``patch_data`` and ``source_data`` arguments.
    """
    del context
    return {"patch_data": bps_patch().hex(), "source_data": SAMPLE.data.hex()}


def _import_ups_arguments(context: RecipeContext) -> dict[str, JsonValue]:
    """Supply an engine-produced UPS patch and the source it applies to.

    Args:
        context: Environment the recipe runs in.

    Returns:
        dict[str, JsonValue]: The ``patch_data`` and ``source_data`` arguments.
    """
    del context
    return {"patch_data": ups_patch().hex(), "source_data": SAMPLE.data.hex()}


def _register_template_arguments(context: RecipeContext) -> dict[str, JsonValue]:
    """Supply a template definition derived from one of the builtins.

    Args:
        context: Environment the recipe runs in.

    Returns:
        dict[str, JsonValue]: The ``json_str`` argument.
    """
    del context
    return {"json_str": custom_template_json()}


_RECIPES: Final[Mapping[str, Recipe]] = MappingProxyType({
    "add_bookmark": _constant(
        Target.SAMPLE,
        offset=_ORIGIN,
        length=_BOOKMARK_LENGTH,
        label=BOOKMARK_LABEL,
        color=BOOKMARK_COLOR,
    ),
    "add_bookmark_object": _constant(
        Target.SAMPLE,
        bookmark={
            "offset": _SECOND_BOOKMARK_OFFSET,
            "length": _BOOKMARK_LENGTH,
            "label": BOOKMARK_LABEL,
            "color": BOOKMARK_COLOR,
        },
    ),
    "add_va_mapping": _constant(Target.SAMPLE, file_offset=_ORIGIN, virtual_address=VA_BASE, length=VA_LENGTH),
    "apply_template": _noted(
        Target.EXECUTABLE,
        "Needs a real PE, so it runs against the interpreter copy rather than the synthetic sample.",
        name=BUILTIN_TEMPLATE,
        offset=_ORIGIN,
    ),
    "byte_distribution_bytes": _noted(
        Target.SAMPLE,
        "The buffer form of byte_distribution_full: 256 little-endian u64 counts, so exactly 2048 bytes.",
    ),
    "byte_distribution_full": _constant(Target.SAMPLE),
    "byte_statistics": _constant(Target.SAMPLE),
    "byte_type_distribution": _constant(Target.SAMPLE),
    "can_redo": _constant(Target.SAMPLE),
    "can_undo": _constant(Target.SAMPLE),
    "close": _noted(
        Target.SAMPLE,
        "Releases the backing file so its path can be rewritten; the document stays describable and a second close is idempotent.",
    ),
    "compute_hash": _constant(Target.SAMPLE, algorithm=HASH_ALGORITHM),
    "compute_hash_custom_crc": _noted(
        Target.SAMPLE,
        "The byte range spans the whole document; an empty range would hash nothing and still return a plausible digest.",
        byte_range=[_ORIGIN, SAMPLE_LENGTH],
        poly=_CRC_POLY,
        init=_CRC_INIT,
        width=_CRC_WIDTH,
        reflect=[True, True],
        xorout=_CRC_XOROUT,
    ),
    "compute_hash_range": _constant(Target.SAMPLE, start=_ORIGIN, end=_HASH_RANGE_END, algorithm=HASH_ALGORITHM),
    "content_classification": _constant(Target.SAMPLE, block_size=BLOCK_SIZE),
    "copy_block": _constant(Target.SAMPLE, src_offset=_ORIGIN, length=_BLOCK_LENGTH, dst_offset=_BLOCK_DESTINATION),
    "decode_text": _constant(Target.SAMPLE, offset=_ORIGIN, length=_DECODE_LENGTH, encoding=TEXT_ENCODING),
    "delete_bytes": _constant(Target.SAMPLE, offset=_DELETE_OFFSET, length=_DELETE_LENGTH),
    "diff_bytes": _constant(Target.NONE, data_a=SAMPLE.data.hex(), data_b=SAMPLE_VARIANT.hex()),
    "diff_files": _built(Target.NONE, _diff_files_arguments),
    "digram_matrix": _constant(Target.SAMPLE),
    "digram_matrix_bytes": _noted(
        Target.SAMPLE,
        "The buffer form of digram_matrix: the 256x256 grid as little-endian u64, so exactly 512 KiB.",
    ),
    "encode_text_to_bytes": _constant(Target.NONE, text=WIDE_TEXT, encoding=TEXT_ENCODING),
    "entropy": _constant(Target.SAMPLE),
    "entropy_map": _constant(Target.SAMPLE, block_size=BLOCK_SIZE),
    "entropy_map_bytes": _noted(
        Target.SAMPLE,
        "The buffer form of entropy_map: one little-endian f64 per block, so eight bytes for every value the list form yields.",
        block_size=BLOCK_SIZE,
    ),
    "export_patches_bps": _constant(Target.SAMPLE, source_data=SAMPLE.data.hex()),
    "export_patches_bps_from_path": _built(Target.SAMPLE, _source_path_arguments),
    "export_patches_cod": _constant(Target.SAMPLE),
    "export_patches_ips": _constant(Target.SAMPLE),
    "export_patches_ips32": _constant(Target.SAMPLE),
    "export_patches_json": _constant(Target.SAMPLE),
    "export_patches_ups": _constant(Target.SAMPLE, source_data=SAMPLE.data.hex()),
    "export_patches_ups_from_path": _built(Target.SAMPLE, _source_path_arguments),
    "export_template_json": _constant(Target.SAMPLE, name=BUILTIN_TEMPLATE),
    "extract_strings": _constant(
        Target.SAMPLE,
        min_length=_MIN_STRING_LENGTH,
        include_ascii=True,
        include_utf16=True,
        max_results=MAX_RESULTS,
    ),
    "file_offset_to_va": _noted(Target.SAMPLE, _FRESH_DOCUMENT_NOTE, offset=_ORIGIN),
    "file_path": _noted(Target.SAMPLE, "An in-memory document has no backing file, so the answer is null."),
    "fill_block": _constant(Target.SAMPLE, offset=_SWAP_SECOND_OFFSET, length=_SWAP_LENGTH, pattern=FILL_PATTERN.hex()),
    "from_process_memory": _tolerant(
        Target.NONE,
        _PROCESS_MEMORY_NOTE,
        _TOLERATE_RUNTIME,
        pid=os.getpid(),
        address=process_probe_address(),
        size=process_probe_size(),
    ),
    "generation": _noted(
        Target.SAMPLE,
        "The engine's own content counter, which the registry's document generation tracks but is not the same number.",
    ),
    "get_bit": _constant(Target.SAMPLE, offset=_ORIGIN, bit_index=_FIRST_INDEX),
    "get_bookmark": _noted(Target.SAMPLE, _FRESH_DOCUMENT_NOTE, index=_FIRST_INDEX),
    "get_bookmarks": _constant(Target.SAMPLE),
    "get_chunk_size_hint": _constant(Target.SAMPLE),
    "get_document_memory_usage": _constant(Target.SAMPLE),
    "get_memory_budget_hint": _constant(Target.SAMPLE),
    "get_patches": _constant(Target.SAMPLE),
    "import_patches_bps": _built(
        Target.SAMPLE,
        _import_bps_arguments,
        "Replaces the document wholesale and clears its undo stack, so the caller must re-read every cached window.",
    ),
    "import_patches_ips": _noted(
        Target.SAMPLE,
        "The patch is built here byte by byte, so a successful import proves the reader parses bytes the engine did not write.",
        data=IPS_PATCH.hex(),
    ),
    "import_patches_ups": _built(
        Target.SAMPLE,
        _import_ups_arguments,
        "Replaces the document wholesale and clears its undo stack, so the caller must re-read every cached window.",
    ),
    "insert_bytes": _constant(Target.SAMPLE, offset=_ORIGIN, data=INSERTED_BYTES.hex()),
    "inspect_at": _noted(
        Target.SAMPLE,
        "The key set varies with how many bytes remain, so an assertion must never fix the row list.",
        offset=_ORIGIN,
    ),
    "is_modified": _constant(Target.SAMPLE),
    "length": _constant(Target.SAMPLE),
    "list_bookmarks": _constant(Target.SAMPLE),
    "list_encodings": _constant(Target.NONE),
    "list_process_memory_regions": _tolerant(Target.NONE, _PROCESS_MEMORY_NOTE, _TOLERATE_RUNTIME, pid=os.getpid()),
    "list_templates": _constant(Target.SAMPLE),
    "list_templates_detailed": _constant(Target.SAMPLE),
    "list_transforms": _constant(Target.NONE),
    "list_va_mappings": _constant(Target.SAMPLE),
    "move_block": _constant(Target.SAMPLE, src_offset=_ORIGIN, length=_BLOCK_LENGTH, dst_offset=_BLOCK_DESTINATION),
    "open": _built(Target.NONE, _open_arguments),
    "open_bytes": _constant(Target.NONE, data=SAMPLE.data.hex()),
    "read": _constant(Target.SAMPLE, offset=_ORIGIN, length=_READ_LENGTH),
    "read_byte": _constant(Target.SAMPLE, offset=_ORIGIN),
    "read_window": _noted(
        Target.SAMPLE,
        "Answers with the bytes, one class tag per byte and the generation they were read at, from a single acquisition.",
        offset=_ORIGIN,
        length=_READ_LENGTH,
    ),
    "redo": _noted(Target.SAMPLE, _FRESH_DOCUMENT_NOTE),
    "register_json_template": _built(Target.SAMPLE, _register_template_arguments),
    "remove_bookmark": _noted(Target.SAMPLE, _FRESH_DOCUMENT_NOTE, index=_FIRST_INDEX),
    "remove_template": _noted(
        Target.SAMPLE,
        "Removes the definition register_json_template installs; returns false when that has not run in this process.",
        name=CUSTOM_TEMPLATE_NAME,
    ),
    "remove_va_mapping": _noted(Target.SAMPLE, _FRESH_DOCUMENT_NOTE, index=_FIRST_INDEX),
    "repair_pe_checksum": _noted(
        Target.EXECUTABLE,
        "Needs a real PE. Afterwards verify_pe_checksum reports the stored and calculated values as equal.",
    ),
    "replace_bytes": _constant(Target.SAMPLE, pattern=NEEDLE.hex(), replacement=REPLACEMENT.hex()),
    "save": _built(Target.SAMPLE, _save_arguments, "Always needs an explicit path, exactly as save_as does."),
    "save_as": _built(Target.SAMPLE, _save_as_arguments),
    "search_bytes": _constant(Target.SAMPLE, pattern=NEEDLE.hex(), max_results=MAX_RESULTS),
    "search_hex": _constant(Target.SAMPLE, pattern=needle_hex(), max_results=MAX_RESULTS),
    "search_numeric": _constant(
        Target.SAMPLE,
        value=NUMERIC_VALUE,
        size=NUMERIC_SIZE,
        signed=False,
        big_endian=False,
        alignment=_ALIGNMENT,
        max_results=MAX_RESULTS,
    ),
    "search_numeric_float": _constant(
        Target.SAMPLE,
        value=FLOAT_VALUE,
        size=FLOAT_SIZE,
        big_endian=False,
        tolerance=_FLOAT_TOLERANCE,
        alignment=_ALIGNMENT,
        max_results=MAX_RESULTS,
    ),
    "search_numeric_range": _constant(
        Target.SAMPLE,
        value_range=[NUMERIC_VALUE - _RANGE_MARGIN, NUMERIC_VALUE + _RANGE_MARGIN],
        size=NUMERIC_SIZE,
        signed=False,
        big_endian=False,
        alignment=_ALIGNMENT,
        max_results=MAX_RESULTS,
    ),
    "search_regex": _constant(Target.SAMPLE, pattern=SEARCH_REGEX, max_results=MAX_RESULTS),
    "search_text": _constant(
        Target.SAMPLE,
        text=NEEDLE.decode("ascii"),
        encoding=TEXT_ENCODING,
        case_sensitive=True,
        max_results=MAX_RESULTS,
    ),
    "search_text_encoded": _constant(
        Target.SAMPLE,
        text=WIDE_TEXT,
        encoding=WIDE_ENCODING,
        case_sensitive=True,
        max_results=MAX_RESULTS,
    ),
    "set_bit": _constant(Target.SAMPLE, offset=_ORIGIN, bit_index=_FIRST_INDEX, value=True),
    "set_chunk_size_hint": _constant(Target.SAMPLE, size=CHUNK_SIZE_HINT),
    "set_memory_budget_hint": _constant(Target.SAMPLE, budget=MEMORY_BUDGET_HINT),
    "swap_blocks": _constant(
        Target.SAMPLE,
        offset_a=_ORIGIN,
        len_a=_SWAP_LENGTH,
        offset_b=_SWAP_SECOND_OFFSET,
        len_b=_SWAP_LENGTH,
    ),
    "toggle_bit": _constant(Target.SAMPLE, offset=_ORIGIN, bit_index=_HIGH_BIT_INDEX),
    "transform_data": _noted(
        Target.SAMPLE,
        "Every params value is raw bytes, so the key is sent hex encoded rather than as text.",
        name=TRANSFORM_NAME,
        offset=TRANSFORM_OFFSET,
        length=TRANSFORM_LENGTH,
        params={"key": TRANSFORM_KEY.hex()},
    ),
    "undo": _noted(Target.SAMPLE, _FRESH_DOCUMENT_NOTE),
    "update_bookmark": _noted(
        Target.SAMPLE,
        _FRESH_DOCUMENT_NOTE,
        index=_FIRST_INDEX,
        bookmark={
            "offset": _ORIGIN,
            "length": _BOOKMARK_LENGTH,
            "label": BOOKMARK_LABEL,
            "color": BOOKMARK_COLOR,
        },
    ),
    "va_to_file_offset": _noted(Target.SAMPLE, _FRESH_DOCUMENT_NOTE, va=VA_BASE),
    "verify_pe_checksum": _noted(
        Target.EXECUTABLE,
        "Needs a real PE. The interpreter image stores a zero checksum, so valid is false until repair_pe_checksum runs.",
    ),
    "write_bytes": _constant(Target.SAMPLE, offset=_ORIGIN, data=WRITTEN_BYTES.hex()),
})

RECIPES: Final[Mapping[str, Recipe]] = _RECIPES
"""One recipe per catalogued operation, keyed by operation name."""


def recipe_for(name: str) -> Recipe:
    """Look up how to invoke one catalogued operation.

    Args:
        name: Operation name as it appears in the catalogue.

    Returns:
        Recipe: The recipe registered for that operation.

    Raises:
        RecipeError: If the table holds no recipe under that name.
    """
    found = _RECIPES.get(name)
    if found is None:
        message = f"no invocation recipe for: [{name!r}]"
        raise RecipeError(message)
    return found


def missing_recipes() -> frozenset[str]:
    """List catalogued operations this table cannot invoke.

    Returns:
        frozenset[str]: Operation names with no recipe, empty when the table is
        complete.
    """
    return operation_names() - frozenset(_RECIPES)


def unknown_recipes() -> frozenset[str]:
    """List recipes that name nothing the engine exposes.

    A non-empty result means an operation was renamed or withdrawn and the
    recipe was left behind, which would otherwise let the coverage count look
    healthy while testing nothing.

    Returns:
        frozenset[str]: Recipe names absent from the catalogue.
    """
    return frozenset(_RECIPES) - operation_names()


def coverage_gap() -> str:
    """Describe any disagreement between the recipe table and the catalogue.

    Returns:
        str: A message naming what is missing or stale, or an empty string when
        every catalogued operation has exactly one live recipe.
    """
    problems: list[str] = []
    missing = missing_recipes()
    if missing:
        problems.append(f"no invocation recipe for: {sorted(missing)}")
    unknown = unknown_recipes()
    if unknown:
        problems.append(f"recipe names no catalogued operation: {sorted(unknown)}")
    return "; ".join(problems)
