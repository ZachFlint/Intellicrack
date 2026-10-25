# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The limits on ``diff_bytes`` and ``diff_files``, and the defaults they rely on.

Two inputs that differ at every other byte have about a million regions, and
every one of them would become a JSON object and a table row. The engine
therefore lists at most ``max_regions`` of them while still counting all, and
folds a short equal run between two changes into one region when ``min_match``
says so. This module drives both through the real dispatcher, over inputs whose
regions are known by construction rather than read back from an earlier run.

Both limits are optional on the engine side, but the catalog lists every
parameter and decoding insists on all of them. The first class holds the piece
that bridges the two, :func:`hexbench.dispatch.with_engine_defaults`, and the
agreement between the defaults the compiled engine declares and the ones its
type stub advertises, since a stub that promises a different default would
mislead every caller that trusts it.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import intellicrack_hexcore

from hexbench.dispatch import operation_for, translate_exception, with_engine_defaults

from ._support import STATIC_ROOT, HexbenchTestCase


if TYPE_CHECKING:
    from hexbench.codec import JsonValue
    from hexbench.dispatch import InvocationResult


_DIFF_BYTES: Final = "diff_bytes"
_DIFF_FILES: Final = "diff_files"
_STUB_NAME: Final = "__init__.pyi"

_DEFAULT_MIN_MATCH: Final = 1
"""``min_match`` the engine uses when none is given."""

_DEFAULT_MAX_REGIONS: Final = 100_000
"""``max_regions`` the engine uses when none is given."""

_STATUS_OK: Final = 200

_SMALL_A: Final[bytes] = b"AAAA-B-CCCC-D-EEEE"
_SMALL_B: Final[bytes] = b"AAAA-X-CCCC-Y-EEEE"
"""Two inputs with exactly two one-byte changes, six equal bytes apart."""

_SMALL_REGIONS: Final = 5
"""Regions of the small pair at the default ``min_match``: three matches, two changes."""

_DENSE_LENGTH: Final = 1 << 20
_DENSE_FIRST: Final = 3
_DENSE_STRIDE: Final = 2
_DENSE_TAIL: Final = 4
_PERIOD: Final = 64
_TOP_BIT: Final = 0x80
"""Set in every other byte of the dense input, so it matches nothing in the original."""


def _fields(result: InvocationResult) -> dict[str, JsonValue]:
    """Read a ``diff_*`` result as the object it is.

    Args:
        result: What the dispatcher returned.

    Returns:
        dict[str, JsonValue]: The result's fields.

    Raises:
        TypeError: If the result is not a JSON object.
    """
    value = result.value
    if not isinstance(value, dict):
        message = f"{result.operation} returned {type(value).__name__}, not an object"
        raise TypeError(message)
    return value


def _regions(fields: dict[str, JsonValue]) -> list[JsonValue]:
    """Read the listed regions out of a ``diff_*`` result.

    Args:
        fields: The fields of the result.

    Returns:
        list[JsonValue]: The listed regions.

    Raises:
        TypeError: If ``regions`` is not a list.
    """
    regions = fields["regions"]
    if not isinstance(regions, list):
        message = f"regions is {type(regions).__name__}, not a list"
        raise TypeError(message)
    return regions


def _dense_pair() -> tuple[bytes, bytes, int]:
    """Build two buffers whose every other byte differs.

    The source repeats a 64-byte period of values below 128 and the copy sets
    the top bit of every other byte from offset 3, so a changed byte equals
    nothing in the source and each change is the only minimal alignment.

    Returns:
        tuple[bytes, bytes, int]: The source, the copy and the number of
        changed bytes.
    """
    source = bytes(index % _PERIOD for index in range(_DENSE_LENGTH))
    edited = bytearray(source)
    positions = range(_DENSE_FIRST, _DENSE_LENGTH - _DENSE_TAIL, _DENSE_STRIDE)
    for position in positions:
        edited[position] |= _TOP_BIT
    return source, bytes(edited), len(positions)


class EngineDefaultTests(HexbenchTestCase):
    """The engine's own defaults must reach the dispatcher and agree with the stub."""

    def test_omitted_limits_are_filled_from_the_engine(self) -> None:
        """A request naming only the inputs gains both limits, with the engine's values."""
        filled = with_engine_defaults(operation_for(_DIFF_BYTES), {"data_a": "00", "data_b": "01"})
        self.equal(
            filled,
            {"data_a": "00", "data_b": "01", "min_match": _DEFAULT_MIN_MATCH, "max_regions": _DEFAULT_MAX_REGIONS},
            "the defaults the dispatcher supplied",
        )
        refilled = with_engine_defaults(operation_for(_DIFF_FILES), {"path_a": "a", "path_b": "b"})
        self.equal(refilled["min_match"], _DEFAULT_MIN_MATCH, "diff_files min_match")
        self.equal(refilled["max_regions"], _DEFAULT_MAX_REGIONS, "diff_files max_regions")

    def test_a_supplied_limit_is_never_replaced(self) -> None:
        """What the request carries wins over the engine's default."""
        filled = with_engine_defaults(operation_for(_DIFF_BYTES), {"data_a": "00", "data_b": "01", "min_match": 7, "max_regions": 0})
        self.equal(filled["min_match"], 7, "supplied min_match")
        self.equal(filled["max_regions"], 0, "supplied max_regions")

    def test_a_required_argument_is_never_invented(self) -> None:
        """Only arguments the engine defaults are filled; the inputs stay required."""
        filled = with_engine_defaults(operation_for(_DIFF_BYTES), {})
        self.absent("data_a", list(filled), "an input the engine does not default")
        self.absent("data_b", list(filled), "an input the engine does not default")
        self.equal(
            with_engine_defaults(operation_for("read"), {"offset": 0, "length": 4}),
            {"offset": 0, "length": 4},
            "an operation with no defaults",
        )

    def test_the_stub_advertises_the_defaults_the_engine_has(self) -> None:
        """Every default written in the type stub is the one the compiled function reports."""
        stub = Path(str(intellicrack_hexcore.__file__)).with_name(_STUB_NAME)
        tree = ast.parse(stub.read_text(encoding="utf-8"))
        compared: set[str] = set()
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or not node.args.defaults:
                continue
            live = inspect.signature(getattr(intellicrack_hexcore, node.name)).parameters
            declared = node.args.args[-len(node.args.defaults) :]
            for parameter, default in zip(declared, node.args.defaults, strict=True):
                self.equal(ast.literal_eval(default), live[parameter.arg].default, f"{node.name}({parameter.arg}) default")
                compared.add(f"{node.name}.{parameter.arg}")
        self.equal(
            compared,
            {f"{name}.{limit}" for name in (_DIFF_BYTES, _DIFF_FILES) for limit in ("min_match", "max_regions")},
            "the defaults the stub declares",
        )

    def test_the_generic_form_starts_from_the_engines_defaults(self) -> None:
        """The operation form must offer the engine's defaults, not zero.

        A number field with no declared default starts at 0, and ``max_regions=0``
        lists no regions at all, so the form would turn every comparison into a
        count. ``forms.js`` therefore names the defaults, and they must be the
        engine's.
        """
        source = (STATIC_ROOT / "forms.js").read_text(encoding="utf-8")
        constants = {"min_match": "DEFAULT_DIFF_MIN_MATCH", "max_regions": "DEFAULT_DIFF_MAX_REGIONS"}
        for limit, constant in constants.items():
            declared = re.search(rf"^const {constant} = (\d+);", source, re.MULTILINE)
            self.require(declared is not None, f"forms.js declares no {constant}")
            value = int(declared.group(1)) if declared is not None else -1
            for name in (_DIFF_BYTES, _DIFF_FILES):
                live = inspect.signature(getattr(intellicrack_hexcore, name)).parameters[limit].default
                self.equal(value, live, f"{constant} against {name}({limit}) in the engine")
                self.require(f"['{name}.{limit}', {constant}]" in source, f"DEFAULT_OVERRIDES has no entry for {name}.{limit}")


class DiffLimitTests(HexbenchTestCase):
    """``min_match`` and ``max_regions`` as the dispatcher and the HTTP surface see them."""

    def _diff(self, data_a: bytes, data_b: bytes, **limits: int) -> dict[str, JsonValue]:
        """Run ``diff_bytes`` and return its fields.

        Args:
            data_a: First input.
            data_b: Second input.
            **limits: ``min_match`` and ``max_regions``, each optional.

        Returns:
            dict[str, JsonValue]: The fields of the result.
        """
        arguments: dict[str, JsonValue] = {"data_a": data_a.hex(), "data_b": data_b.hex(), **limits}
        return _fields(self.session.call(_DIFF_BYTES, arguments))

    def test_a_call_without_limits_lists_every_region(self) -> None:
        """Leaving both limits out is a complete, untruncated comparison."""
        fields = self._diff(_SMALL_A, _SMALL_B)
        self.equal(len(_regions(fields)), _SMALL_REGIONS, "listed regions")
        self.equal(fields["region_count"], _SMALL_REGIONS, "region_count")
        self.equal(fields["change_count"], 2, "change_count")
        self.equal(fields["total_differences"], 2, "total_differences")
        self.falsy(fields["truncated"], "truncated")

    def test_the_http_surface_accepts_a_call_without_limits(self) -> None:
        """The same call over HTTP is not refused for missing arguments."""
        response = self.session.post_operation(_DIFF_BYTES, {"data_a": _SMALL_A.hex(), "data_b": _SMALL_B.hex()})
        self.equal(response.status, _STATUS_OK, "status of a diff_bytes call that names only its inputs")

    def test_regions_past_the_cap_are_counted_not_listed(self) -> None:
        """A cap of two lists two regions and still reports all five."""
        fields = self._diff(_SMALL_A, _SMALL_B, max_regions=2)
        self.equal(len(_regions(fields)), 2, "listed regions")
        self.equal(fields["region_count"], _SMALL_REGIONS, "region_count")
        self.equal(fields["change_count"], 2, "change_count")
        self.equal(fields["total_differences"], 2, "total_differences")
        self.truthy(fields["truncated"], "truncated")

    def test_a_short_gap_folds_into_one_region(self) -> None:
        """A minimum match above the six equal bytes between the changes merges them."""
        fields = self._diff(_SMALL_A, _SMALL_B, min_match=7)
        regions = _regions(fields)
        self.equal(len(regions), 3, "listed regions")
        self.equal(fields["change_count"], 1, "change_count")
        self.equal(fields["total_differences"], 2, "total_differences is not inflated by the folded gap")
        self.equal(self._diff(_SMALL_A, _SMALL_B, min_match=6)["change_count"], 2, "a gap of exactly min_match is kept")

    def test_a_negative_limit_is_refused_as_a_bad_value(self) -> None:
        """A negative limit is refused by the engine and classified as a client error."""
        for limit in ("min_match", "max_regions"):
            with self.subTest(limit=limit):
                message = self.refusal(
                    OverflowError,
                    f"a negative {limit}",
                    lambda name=limit: self._diff(_SMALL_A, _SMALL_B, **{name: -1}),
                )
                self.equal(translate_exception(OverflowError(message)).kind, "value", "classification of a negative limit")

    def test_every_other_byte_differing_is_bounded_at_the_default_cap(self) -> None:
        """Two 1 MiB inputs differing at every other byte list 100000 of about a million regions."""
        source, edited, changes = _dense_pair()
        fields = self._diff(source, edited)
        self.equal(len(_regions(fields)), _DEFAULT_MAX_REGIONS, "listed regions")
        self.equal(fields["region_count"], 2 * changes + 1, "region_count")
        self.equal(fields["change_count"], changes, "change_count")
        self.equal(fields["total_differences"], changes, "total_differences stays exact past the cap")
        self.truthy(fields["truncated"], "truncated")
        self.exceeds(int(str(fields["region_count"])), 1_000_000, "the comparison is the million-region case")
