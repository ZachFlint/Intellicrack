# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for sandbox network and YARA log helpers.

Verifies the pure-Python primitives shared between
:mod:`intellicrack.sandbox.windows` and :mod:`intellicrack.sandbox.qemu`:

- ``split_addr_port`` IPv4/IPv6/edge handling
- ``coerce_protocol`` normalization to canonical literals
- ``infer_direction`` listener vs outbound classification
- ``safe_int``/``safe_float`` numeric coercion with fallback
- ``format_yara_match`` serialization of yara.Match objects
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Final, Protocol

from intellicrack.sandbox._log_helpers import (
    YARA_MATCH_MIN_FIELDS,
    coerce_protocol,
    format_yara_match,
    infer_direction,
    safe_float,
    safe_int,
    split_addr_port,
)


class _YaraStringsEntry(Protocol):
    """Tuple-shaped duck type expected by ``format_yara_match``.

    Attributes are accessed positionally via ``__getitem__`` and the
    entry length is reported via ``__len__``; entries shorter than
    ``YARA_MATCH_MIN_FIELDS`` are skipped.
    """

    def __len__(self) -> int:
        """Return the number of tuple-like fields.

        Returns:
            int: Field count consumed by ``format_yara_match``.
        """
        ...

    def __getitem__(self, index: int) -> int | str | bytes:
        """Return the value at ``index``.

        Args:
            index: Zero-based field index.

        Returns:
            int | str | bytes: Field value at ``index``.
        """
        ...


_IPV4_OFFSET: Final[int] = 0x1000
_IPV4_PORT: Final[int] = 443
_IPV6_PORT: Final[int] = 8443
_FLOAT_TOLERANCE: Final[float] = 1e-9


def _approx_equal(actual: float, expected: float) -> bool:
    """Compare two floats with a tight absolute tolerance.

    Args:
        actual: Value produced by code under test.
        expected: Expected reference value.

    Returns:
        bool: True if the values match within ``_FLOAT_TOLERANCE``.
    """
    return math.isclose(actual, expected, abs_tol=_FLOAT_TOLERANCE)


class TestSplitAddrPort:
    """Tests for the ``split_addr_port`` helper."""

    def test_empty_input(self) -> None:
        """Empty input returns ``("", 0)``."""
        assert split_addr_port("") == ("", 0)

    def test_ipv4_address_with_port(self) -> None:
        """IPv4 ``addr:port`` splits at the final colon."""
        assert split_addr_port("192.168.1.100:443") == ("192.168.1.100", _IPV4_PORT)

    def test_ipv4_address_without_port(self) -> None:
        """Bare IPv4 with no colon returns the whole string and port 0."""
        assert split_addr_port("10.0.0.1") == ("10.0.0.1", 0)

    def test_ipv6_bracketed_with_port(self) -> None:
        """Bracketed IPv6 keeps the address and parses the trailing port."""
        assert split_addr_port("[::1]:8443") == ("::1", _IPV6_PORT)

    def test_ipv6_bracketed_loopback_port_zero(self) -> None:
        """IPv6 with a non-numeric port returns 0 for the port."""
        assert split_addr_port("[fe80::1]:nope") == ("fe80::1", 0)

    def test_ipv6_unbracketed_uses_rpartition(self) -> None:
        """Unbracketed IPv6 splits at the LAST colon (best-effort)."""
        addr, port = split_addr_port("fe80::1:80")
        assert port == 80
        assert addr == "fe80::1"

    def test_port_with_whitespace(self) -> None:
        """Whitespace around the port is tolerated."""
        assert split_addr_port("10.0.0.5: 22") == ("10.0.0.5", 22)

    def test_non_numeric_port(self) -> None:
        """Non-numeric port falls back to 0 without raising."""
        assert split_addr_port("host.example.com:abc") == ("host.example.com", 0)


class TestCoerceProtocol:
    """Tests for the ``coerce_protocol`` helper."""

    def test_tcp_lowercase(self) -> None:
        """Plain ``tcp`` returns ``tcp``."""
        assert coerce_protocol("tcp") == "tcp"

    def test_tcp_uppercase(self) -> None:
        """Upper-case ``TCP`` is normalized to ``tcp``."""
        assert coerce_protocol("TCP") == "tcp"

    def test_udp_with_whitespace(self) -> None:
        """Whitespace around ``udp`` is stripped."""
        assert coerce_protocol("  udp  ") == "udp"

    def test_icmp(self) -> None:
        """``icmp`` round-trips."""
        assert coerce_protocol("ICMP") == "icmp"

    def test_unknown_protocol(self) -> None:
        """Anything else maps to ``other``."""
        assert coerce_protocol("sctp") == "other"

    def test_empty_string(self) -> None:
        """Empty input maps to ``other``."""
        assert coerce_protocol("") == "other"


class TestInferDirection:
    """Tests for the ``infer_direction`` helper."""

    def test_listen_is_inbound(self) -> None:
        """``listen`` -> ``inbound``."""
        assert infer_direction("listen") == "inbound"

    def test_bound_is_inbound(self) -> None:
        """``bound`` -> ``inbound``."""
        assert infer_direction("bound") == "inbound"

    def test_listen_uppercase_is_inbound(self) -> None:
        """``LISTEN`` is normalized to lowercase before checking."""
        assert infer_direction("LISTEN") == "inbound"

    def test_bound_with_whitespace_is_inbound(self) -> None:
        """Whitespace is stripped before classification."""
        assert infer_direction("  Bound\n") == "inbound"

    def test_established_is_outbound(self) -> None:
        """``established`` -> ``outbound``."""
        assert infer_direction("established") == "outbound"

    def test_time_wait_is_outbound(self) -> None:
        """``time_wait`` -> ``outbound``."""
        assert infer_direction("time_wait") == "outbound"

    def test_empty_state_is_outbound(self) -> None:
        """Empty state defaults to ``outbound``."""
        assert infer_direction("") == "outbound"


class TestSafeInt:
    """Tests for the ``safe_int`` helper."""

    def test_plain_integer(self) -> None:
        """Plain digit string parses cleanly."""
        assert safe_int("42") == 42

    def test_negative_integer(self) -> None:
        """Negative integer literals parse cleanly."""
        assert safe_int("-7") == -7

    def test_float_string_falls_through(self) -> None:
        """Float-shaped strings round-trip through ``int(float(...))``."""
        assert safe_int("3.0") == 3

    def test_empty_string_returns_zero(self) -> None:
        """Empty string returns 0."""
        assert safe_int("") == 0

    def test_whitespace_only_returns_zero(self) -> None:
        """Whitespace-only input returns 0."""
        assert safe_int("   ") == 0

    def test_non_numeric_returns_zero(self) -> None:
        """Non-numeric input returns 0 without raising."""
        assert safe_int("not-a-number") == 0

    def test_hex_returns_zero(self) -> None:
        """Hex-prefixed input is not parsed (returns 0)."""
        assert safe_int("0x10") == 0

    def test_whitespace_around_value(self) -> None:
        """Surrounding whitespace is stripped."""
        assert safe_int("  4096  ") == _IPV4_OFFSET


class TestSafeFloat:
    """Tests for the ``safe_float`` helper."""

    def test_plain_float(self) -> None:
        """Plain float string parses cleanly."""
        assert _approx_equal(safe_float("2.5"), 2.5)

    def test_integer_as_float(self) -> None:
        """Integer-shaped string parses to a float."""
        assert _approx_equal(safe_float("42"), 42.0)

    def test_empty_string_returns_zero(self) -> None:
        """Empty string returns ``0.0``."""
        assert _approx_equal(safe_float(""), 0.0)

    def test_whitespace_only_returns_zero(self) -> None:
        """Whitespace-only input returns ``0.0``."""
        assert _approx_equal(safe_float("\t"), 0.0)

    def test_non_numeric_returns_zero(self) -> None:
        """Non-numeric input returns ``0.0`` without raising."""
        assert _approx_equal(safe_float("nan-text"), 0.0)

    def test_negative_float(self) -> None:
        """Negative floats parse cleanly."""
        assert _approx_equal(safe_float("-1.5"), -1.5)


@dataclass(frozen=True)
class _MatchString:
    """Tuple-shaped mimic of the legacy ``yara.Match`` strings entry.

    Attributes:
        offset: Byte offset where the match occurred.
        identifier: YARA string identifier (``$name``).
        data: Matched data, either ``bytes`` or text.
    """

    offset: int
    identifier: str
    data: bytes | str

    def __len__(self) -> int:
        """Return the entry length for ``len()`` compatibility.

        Returns:
            int: Always 3 (matching the legacy YARA tuple shape).
        """
        return 3

    def __getitem__(self, index: int) -> int | str | bytes:
        """Provide tuple-style indexed access.

        Args:
            index: Zero-based field index.

        Returns:
            int | str | bytes: The value at ``index``.
        """
        return (self.offset, self.identifier, self.data)[index]


@dataclass
class _Match:
    """Minimal duck-typed yara.Match used by the helpers.

    Attributes:
        rule: YARA rule name.
        namespace: Namespace label.
        tags: Sequence of tag strings.
        strings: Match-string entries.
    """

    rule: str
    namespace: str
    tags: list[str] = field(default_factory=list)
    strings: list[_YaraStringsEntry] = field(default_factory=list)


@dataclass(frozen=True)
class _ShortEntry:
    """Two-element entry that should be skipped by the formatter.

    Attributes:
        offset: Byte offset (used to mimic the YARA tuple).
        identifier: Identifier text.
    """

    offset: int
    identifier: str

    def __len__(self) -> int:
        """Return the entry length.

        Returns:
            int: Always 2 (below ``YARA_MATCH_MIN_FIELDS``).
        """
        return 2

    def __getitem__(self, index: int) -> int | str:
        """Return tuple-like fallback values.

        Args:
            index: Field index.

        Returns:
            int | str: Value at ``index``.
        """
        return (self.offset, self.identifier)[index]


class _Bare:
    """Object with no YARA attributes (forces all defaults)."""


class TestFormatYaraMatch:
    """Tests for the ``format_yara_match`` helper."""

    def test_minimum_field_constant(self) -> None:
        """Sanity check that the public minimum-field constant is 3."""
        assert YARA_MATCH_MIN_FIELDS == 3

    def test_full_match_with_bytes(self) -> None:
        """Bytes ``data`` is returned as a hex-encoded string."""
        match = _Match(
            "DetectMZ",
            "default",
            ["pe", "windows"],
            [_MatchString(_IPV4_OFFSET, "$mz", b"MZ")],
        )
        result = format_yara_match(match, "C:\\sample.exe", "files")
        assert result["rule"] == "DetectMZ"
        assert result["namespace"] == "default"
        assert result["tags"] == ["pe", "windows"]
        assert result["source"] == "C:\\sample.exe"
        assert result["scan_type"] == "files"
        assert result["strings"] == [
            {
                "offset": _IPV4_OFFSET,
                "identifier": "$mz",
                "data": "4d5a",
            },
        ]

    def test_text_data_is_stringified(self) -> None:
        """Non-bytes ``data`` is coerced via ``str``."""
        match = _Match(
            "TextRule",
            "ns",
            [],
            [_MatchString(0x100, "$t", "literal")],
        )
        result = format_yara_match(match, "memdump.raw", "memory")
        assert result["strings"][0]["data"] == "literal"
        assert result["scan_type"] == "memory"

    def test_skips_short_strings_entry(self) -> None:
        """Tuple-like entries shorter than 3 fields are skipped."""
        match = _Match("Skip", "ns", [], [_ShortEntry(0, "$x")])
        result = format_yara_match(match, "f", "files")
        assert result["strings"] == []

    def test_missing_attributes_default(self) -> None:
        """Missing optional attributes default to empty/blank values."""
        result = format_yara_match(_Bare(), "src", "files")
        assert not result["rule"]
        assert not result["namespace"]
        assert result["tags"] == []
        assert result["strings"] == []
        assert result["source"] == "src"
        assert result["scan_type"] == "files"

    def test_multiple_strings_preserve_order(self) -> None:
        """Multiple matched strings appear in input order."""
        match = _Match(
            "Multi",
            "ns",
            [],
            [
                _MatchString(0x10, "$a", b"\x00\x01"),
                _MatchString(0x20, "$b", "abc"),
            ],
        )
        result = format_yara_match(match, "src", "files")
        assert [s["identifier"] for s in result["strings"]] == ["$a", "$b"]
        assert result["strings"][0]["data"] == "0001"
        assert result["strings"][1]["data"] == "abc"
