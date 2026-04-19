# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live round-trip tests for the .env loader/writer (Unit 9, C34).

Verifies the round-trip property
``parse(write({key: value})) == {key: value}`` across a wide range of value
shapes including empty, whitespace-only, quotes, hashes, embedded newlines,
and unicode. Also exercises the writer's handling of mixed quoted/unquoted
existing content and its preservation of existing end-of-line style.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.credentials.env_loader import CredentialLoader


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_env_loader_module = importlib.import_module("intellicrack.credentials.env_loader")
_quote_env_value = cast(
    "Callable[[str], str]",
    getattr(_env_loader_module, "_quote_env_value"),
)
_parse_env_text = cast(
    "Callable[[str], dict[str, str]]",
    getattr(_env_loader_module, "_parse_env_text"),
)


_ROUND_TRIP_VALUES: list[tuple[str, str]] = [
    ("empty", ""),
    ("plain_ascii", "hello"),
    ("safe_token", "sk-ant-api03-AbC_123.xyz/def-ghi"),
    ("spaces", "value with spaces"),
    ("leading_trailing_ws", "   padded value   "),
    ("tab_only", "\t"),
    ("hash_char", "value#with#hash"),
    ("inline_hash_space", "value # looks like comment"),
    ("single_quotes", "it's a 'quoted' thing"),
    ("double_quotes", 'she said "hi" loudly'),
    ("both_quotes", "mix of 'single' and \"double\" quotes"),
    ("backslash", r"C:\Users\zach\project"),
    ("double_backslash", r"a\\b\\c"),
    ("dollar_sign", "price=$100 for $product"),
    ("newline_n", "line1\nline2\nline3"),
    ("carriage_return", "line1\rline2"),
    ("crlf", "line1\r\nline2"),
    ("tab_embedded", "col1\tcol2\tcol3"),
    ("mixed_escapes", 'tabs\tand\nnewlines\rand\\backslashes and $dollars and "quotes"'),
    ("unicode_basic", "héllo wörld"),
    ("unicode_emoji_text", "name: 日本語"),
    ("url_with_query", "https://example.com/path?key=value&other=1"),
    ("json_like", '{"key": "value", "n": 42}'),
    ("all_specials", '\\"$\n\r\t end'),
]


@pytest.mark.parametrize(("label", "value"), _ROUND_TRIP_VALUES, ids=[row[0] for row in _ROUND_TRIP_VALUES])
def test_quote_then_parse_round_trip(label: str, value: str) -> None:
    """Assert the quoter output parses back to the original value.

    Args:
        label: Human-readable label for the test case (used as pytest id).
        value: The value to round-trip through quoter and parser.
    """
    del label
    quoted = _quote_env_value(value)
    text = f"KEY={quoted}\n"
    parsed = _parse_env_text(text)
    assert parsed == {"KEY": value}


@pytest.mark.parametrize(("label", "value"), _ROUND_TRIP_VALUES, ids=[row[0] for row in _ROUND_TRIP_VALUES])
def test_save_to_env_file_round_trip(tmp_path: Path, label: str, value: str) -> None:
    """Assert ``save_to_env_file`` followed by reload yields the original value.

    Args:
        tmp_path: pytest-provided temporary directory for the .env file.
        label: Human-readable label for the test case.
        value: The value to round-trip via :class:`CredentialLoader`.
    """
    del label
    env_path = tmp_path / ".env"
    env_path.write_text("", encoding="utf-8")

    loader = CredentialLoader(env_path=env_path)
    loader.save_to_env_file("ROUND_TRIP_KEY", value)

    reloaded = CredentialLoader(env_path=env_path)
    assert reloaded.get_env_var("ROUND_TRIP_KEY") == value


def test_save_to_env_file_update_preserves_other_lines(tmp_path: Path) -> None:
    """Ensure updating a key does not touch comments or sibling variables.

    Args:
        tmp_path: pytest-provided temporary directory.
    """
    env_path = tmp_path / ".env"
    initial = '# Intellicrack credentials\nOTHER_KEY=unchanged_value\nQUOTED_KEY="original"\n# trailing comment\n'
    env_path.write_text(initial, encoding="utf-8")

    loader = CredentialLoader(env_path=env_path)
    new_value = 'multi "line" value\nwith embedded newline and $var'
    loader.save_to_env_file("QUOTED_KEY", new_value)

    text_after = env_path.read_text(encoding="utf-8")
    assert "# Intellicrack credentials" in text_after
    assert "OTHER_KEY=unchanged_value" in text_after
    assert "# trailing comment" in text_after

    reloaded = CredentialLoader(env_path=env_path)
    assert reloaded.get_env_var("OTHER_KEY") == "unchanged_value"
    assert reloaded.get_env_var("QUOTED_KEY") == new_value


def test_save_to_env_file_preserves_crlf_line_endings(tmp_path: Path) -> None:
    """Writer keeps CRLF line endings when the source file uses them.

    Args:
        tmp_path: pytest-provided temporary directory.
    """
    env_path = tmp_path / ".env"
    env_path.write_bytes(b"# header\r\nKEY_A=alpha\r\nKEY_B=beta\r\n")

    loader = CredentialLoader(env_path=env_path)
    loader.save_to_env_file("KEY_A", "alpha prime")

    raw = env_path.read_bytes()
    assert b"\r\n" in raw
    assert b"\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")

    reloaded = CredentialLoader(env_path=env_path)
    assert reloaded.get_env_var("KEY_A") == "alpha prime"
    assert reloaded.get_env_var("KEY_B") == "beta"


def test_save_to_env_file_new_file_uses_lf(tmp_path: Path) -> None:
    """Writer uses LF when creating a brand-new .env file.

    Args:
        tmp_path: pytest-provided temporary directory.
    """
    env_path = tmp_path / ".env"
    loader = CredentialLoader(env_path=env_path)
    loader.save_to_env_file("FRESH_KEY", "fresh value")

    raw = env_path.read_bytes()
    assert b"\r\n" not in raw
    assert raw.endswith(b"\n")

    reloaded = CredentialLoader(env_path=env_path)
    assert reloaded.get_env_var("FRESH_KEY") == "fresh value"


def test_parse_mixed_quoted_and_unquoted(tmp_path: Path) -> None:
    """Parser handles a happy-path mix of unquoted, single, and double quotes.

    Args:
        tmp_path: pytest-provided temporary directory.
    """
    env_path = tmp_path / ".env"
    env_path.write_text(
        "# A mixed-style env file\n"
        "UNQUOTED=simple_value\n"
        'DOUBLE="quoted value"\n'
        "SINGLE='single quoted'\n"
        "EXPORTED=exported_token\n"
        "export ALSO_EXPORTED=with_export_prefix\n"
        'ESCAPES="line1\\nline2\\twith\\\\slashes\\$var"\n'
        "INLINE=value # trailing comment\n"
        "\n"
        "EMPTY=\n",
        encoding="utf-8",
    )

    loader = CredentialLoader(env_path=env_path)
    assert loader.get_env_var("UNQUOTED") == "simple_value"
    assert loader.get_env_var("DOUBLE") == "quoted value"
    assert loader.get_env_var("SINGLE") == "single quoted"
    assert loader.get_env_var("EXPORTED") == "exported_token"
    assert loader.get_env_var("ALSO_EXPORTED") == "with_export_prefix"
    assert loader.get_env_var("ESCAPES") == "line1\nline2\twith\\slashes$var"
    assert loader.get_env_var("INLINE") == "value"
    assert not loader.get_env_var("EMPTY")


def test_parser_accepts_crlf_file(tmp_path: Path) -> None:
    """Parser accepts CRLF line endings transparently.

    Args:
        tmp_path: pytest-provided temporary directory.
    """
    env_path = tmp_path / ".env"
    env_path.write_bytes(b'KEY_A=alpha\r\nKEY_B="beta with space"\r\n')

    loader = CredentialLoader(env_path=env_path)
    assert loader.get_env_var("KEY_A") == "alpha"
    assert loader.get_env_var("KEY_B") == "beta with space"


def test_quote_env_value_unquoted_safe_chars() -> None:
    """Safe values (alnum plus ._/-) are emitted without quotes."""
    for safe in ("abc", "A1_b.c-d/e", "sk-ant-api03-xyz", "123.456"):
        assert _quote_env_value(safe) == safe


def test_quote_env_value_quotes_when_needed() -> None:
    """Unsafe values are wrapped in double quotes with correct escapes."""
    assert _quote_env_value("with space") == '"with space"'
    assert _quote_env_value('has "quote"') == '"has \\"quote\\""'
    assert _quote_env_value("has $dollar") == '"has \\$dollar"'
    assert _quote_env_value("has\\backslash") == '"has\\\\backslash"'
    assert _quote_env_value("a\nb") == '"a\\nb"'
    assert _quote_env_value("a\rb") == '"a\\rb"'
    assert _quote_env_value("a\tb") == '"a\\tb"'


def test_quote_env_value_empty() -> None:
    """Empty values serialize to an empty string (bare ``KEY=``)."""
    assert not _quote_env_value("")
    assert _parse_env_text("KEY=\n") == {"KEY": ""}
