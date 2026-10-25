# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gates for encoding transform-panel fields into hexcore transform parameters.

The panel used to send every field as the UTF-8 bytes of its text, so a
rotation of ``13`` reached the engine as ``b"13"`` (whose first byte is
``0x31``, a rotation of 23), and it had no parameter fields at all for the
engine's own transforms, whose names it did not know. The encoder now follows
the engine's parameter catalogue and these tests run real transforms through
``HexDocument.transform_data`` with its output.
"""

from __future__ import annotations

import pytest
from intellicrack_hexcore import HexDocument

from intellicrack.ui.panels.hex_editor.transforms import (
    ENGINE_TRANSFORM_PARAMS,
    EngineParamKind,
    encode_engine_param,
    encode_engine_params,
)


def test_one_byte_parameters_are_numbers_not_text() -> None:
    """``13`` is the byte 13, decimal or hex, never the two ASCII digits."""
    assert encode_engine_param("shift", EngineParamKind.BYTE, "13") == b"\x0d"
    assert encode_engine_param("key", EngineParamKind.BYTE, "0x41") == b"\x41"
    assert encode_engine_param("count", EngineParamKind.BYTE, " 7 ") == b"\x07"


@pytest.mark.parametrize("text", ["256", "-1", "abc", ""])
def test_one_byte_parameter_rejects_out_of_range_and_garbage(text: str) -> None:
    """A value that is not a byte is rejected instead of being truncated.

    Args:
        text: Field text that cannot encode one byte.
    """
    with pytest.raises(ValueError, match="shift"):
        encode_engine_param("shift", EngineParamKind.BYTE, text)


def test_hex_and_choice_parameters() -> None:
    """Byte strings accept separators and a ``0x`` prefix; choices are validated."""
    assert encode_engine_param("key", EngineParamKind.HEX, "0x00 11:22-33") == b"\x00\x11\x22\x33"
    assert encode_engine_param("padding", EngineParamKind.CHOICE, "PKCS7") == b"pkcs7"
    with pytest.raises(ValueError, match="padding must be one of"):
        encode_engine_param("padding", EngineParamKind.CHOICE, "rot13")


def test_rot_n_from_panel_fields_matches_engine_rotation() -> None:
    """A panel rotation of 13 produces ROT13, not the ROT23 the UTF-8 text produced."""
    doc = HexDocument.open_bytes(b"Hello")
    params = encode_engine_params("rot_n", {"shift": "13"})
    assert params == {"shift": b"\x0d"}
    assert doc.transform_data("rot_n", 0, 5, params) == b"Uryyb"


def test_blank_optional_fields_fall_back_to_engine_defaults() -> None:
    """A blank ``increment`` is omitted so the engine's default of 1 applies."""
    doc = HexDocument.open_bytes(b"\x00\x00\x00")
    params = encode_engine_params("xor_rolling", {"key": "0x10", "increment": ""})
    assert params == {"key": b"\x10"}
    assert doc.transform_data("xor_rolling", 0, 3, params) == b"\x10\x11\x12"


def test_catalogue_covers_every_parameterized_engine_transform() -> None:
    """Every engine transform that needs a parameter has panel fields for it."""
    doc = HexDocument.open_bytes(b"\x00" * 16)
    missing: list[str] = []
    for name, _category, _description in HexDocument.list_transforms():
        if name in ENGINE_TRANSFORM_PARAMS:
            continue
        try:
            doc.transform_data(name, 0, 16, {})
        except ValueError as exc:
            if "missing parameter" in str(exc):
                missing.append(name)
    assert missing == []
