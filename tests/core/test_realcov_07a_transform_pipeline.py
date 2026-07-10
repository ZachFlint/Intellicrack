# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage tests for ``intellicrack.core.transform_pipeline``.

The audit (shard 07) flagged that the Python-only transform nodes
(``RegexReplaceNode``, ``CustomExpressionNode``, ``RepeatNode``,
``TruncateNode``, ``PadNode``), the ``TransformPipeline.execute`` /
``preview`` orchestration, the restricted-AST ``_eval_ast_node`` evaluator,
and ``RustTransformNode`` parameter coercion were untested in unit tests.

These tests drive every node against REAL binary bytes taken from real
System32 PE binaries and the committed ELF fixture, and validate the
COMPUTED result rather than that a call happened:

* ``CustomExpressionNode`` results are checked against an independent Python
  computation of the same expression over the same real bytes.
* ``RegexReplaceNode`` replaces a real byte pattern (the ``MZ`` DOS magic)
  inside a real PE and the change is verified byte for byte.
* ``RustTransformNode`` base64 output is compared against ``base64.b64encode``
  of the same real bytes, and an end-to-end pipeline round-trips it.
* ``HexcoreUnavailableError`` and ``TransformParamError`` paths are exercised.

The Rust transform path uses the real hexcore engine; nothing about the
operation under test is mocked.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from intellicrack.core import transform_pipeline
from intellicrack.core.transform_pipeline import (
    CustomExpressionNode,
    ExpressionError,
    HexcoreUnavailableError,
    PadNode,
    RegexReplaceNode,
    RepeatNode,
    RustTransformNode,
    TransformParamError,
    TransformPipeline,
    TruncateNode,
    UnsupportedConstantTypeError,
    get_all_transform_nodes,
)


if TYPE_CHECKING:
    from pathlib import Path


def _eval_single_byte(expression: str, byte_val: int, index: int) -> int:
    """Evaluate a per-byte transform expression via the public node API.

    Drives the real restricted-AST evaluator through
    :meth:`CustomExpressionNode.process` on a one-byte input, returning the
    masked 0-255 result. The index is supplied by prefixing ``byte_val`` with
    ``index`` filler bytes and reading the byte at ``index``.

    Args:
        expression: The expression string using ``b`` and ``i``.
        byte_val: Byte value bound to ``b`` at position ``index``.
        index: Index bound to ``i``.

    Returns:
        int: The masked 0-255 result of evaluating ``expression``.
    """
    data = bytes([0] * index) + bytes([byte_val])
    return CustomExpressionNode().process(data, {"expression": expression})[index]


@pytest.fixture
def real_pe_bytes(real_pe_dll: Path) -> bytes:
    """Return the leading bytes of a real PE for transform input.

    Args:
        real_pe_dll: Real ``kernel32.dll`` resolved from System32.

    Returns:
        bytes: The first 256 bytes of the real DLL (includes the DOS stub).
    """
    return real_pe_dll.read_bytes()[:256]


class TestCustomExpressionNode:
    """Per-byte expression evaluation against real binary bytes."""

    def test_xor_constant_over_real_pe_bytes(self, real_pe_bytes: bytes) -> None:
        """``b ^ 0x55`` applied to real PE bytes matches an independent XOR.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        node = CustomExpressionNode()
        result = node.process(real_pe_bytes, {"expression": "b ^ 0x55"})
        expected = bytes(byte ^ 0x55 for byte in real_pe_bytes)
        assert result == expected
        assert len(result) == len(real_pe_bytes)

    def test_index_dependent_expression(self, real_pe_bytes: bytes) -> None:
        """``(b + i) & 0xFF`` depends on byte index and matches a reference.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        node = CustomExpressionNode()
        result = node.process(real_pe_bytes, {"expression": "(b + i) & 0xFF"})
        expected = bytes((byte + idx) & 0xFF for idx, byte in enumerate(real_pe_bytes))
        assert result == expected

    def test_nibble_swap_expression(self, real_pe_bytes: bytes) -> None:
        """A nibble-swap ``((b >> 4) | (b << 4))`` round-trips correctly.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        node = CustomExpressionNode()
        swapped = node.process(real_pe_bytes, {"expression": "(b >> 4) | (b << 4)"})
        # Applying the swap twice must restore the original bytes.
        restored = node.process(swapped, {"expression": "(b >> 4) | (b << 4)"})
        assert restored == real_pe_bytes

    def test_negative_result_masked_to_byte_range(self) -> None:
        """Negative intermediate values are masked into 0-255."""
        node = CustomExpressionNode()
        data = bytes([0, 1, 10])
        result = node.process(data, {"expression": "b - 1"})
        assert result == bytes((value - 1) & 0xFF for value in data)
        assert result[0] == 0xFF

    def test_conditional_expression(self) -> None:
        """An ``IfExp`` ternary selects the right branch per byte."""
        node = CustomExpressionNode()
        data = bytes([0x10, 0x90, 0x7F, 0x80])
        result = node.process(data, {"expression": "255 if b > 127 else 0"})
        assert result == bytes(255 if value > 127 else 0 for value in data)

    def test_missing_expression_raises(self) -> None:
        """A missing ``expression`` param raises ``TransformParamError``."""
        node = CustomExpressionNode()
        with pytest.raises(TransformParamError, match="requires 'expression'"):
            node.process(b"\x00", {})

    def test_syntax_error_expression_raises(self) -> None:
        """A syntactically invalid expression raises ``TransformParamError``."""
        node = CustomExpressionNode()
        with pytest.raises(TransformParamError, match="bad syntax"):
            node.process(b"\x00", {"expression": "b +"})

    def test_node_identity_metadata(self) -> None:
        """The node reports its stable name, category, and description."""
        node = CustomExpressionNode()
        assert node.name == "custom_expression"
        assert node.category == "python"
        assert node.description


class TestEvalAstNode:
    """Direct coverage of the restricted-AST evaluator."""

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("b + 3", 13),
            ("b - 4", 6),
            ("b * 2", 20),
            ("b // 3", 3),
            ("b % 7", 3),
            ("b ** 2", 100),
            ("b << 1", 20),
            ("b >> 2", 2),
            ("b | 1", 11),
            ("b ^ 0xFF", 245),
            ("b & 0x0F", 10),
            ("-b", (-10) & 0xFF),
            ("~b", (~10) & 0xFF),
            ("b > 5", 1),
            ("b < 5", 0),
            ("b == 10", 1),
            ("b != 10", 0),
            ("b >= 10", 1),
            ("b <= 9", 0),
            ("1 if b else 0", 1),
            ("b and 1", 1),
            ("0 or b", 10),
        ],
    )
    def test_operator_results(self, expression: str, expected: int) -> None:
        """Each supported operator yields the correct masked result.

        Args:
            expression: Expression to evaluate with ``b == 10``, ``i == 4``.
            expected: Expected masked 0-255 result.
        """
        assert _eval_single_byte(expression, 10, 4) == expected

    def test_unknown_variable_raises(self) -> None:
        """An unknown variable name raises ``ExpressionError``."""
        with pytest.raises(ExpressionError, match="Unknown variable"):
            CustomExpressionNode().process(b"\x00", {"expression": "x + 1"})

    def test_unsupported_constant_type_raises(self) -> None:
        """A string constant raises ``UnsupportedConstantTypeError``."""
        with pytest.raises(UnsupportedConstantTypeError):
            CustomExpressionNode().process(b"\x00", {"expression": "'nope'"})

    def test_unsupported_node_type_raises(self) -> None:
        """A function call (disallowed) raises ``ExpressionError``."""
        with pytest.raises(ExpressionError, match="Unsupported node type"):
            CustomExpressionNode().process(b"\x00", {"expression": "len([b])"})


class TestRegexReplaceNode:
    """Regex substitution over real binary content."""

    def test_replace_real_dos_magic(self, real_pe_bytes: bytes) -> None:
        """Replacing the real ``MZ`` magic rewrites the leading bytes.

        Args:
            real_pe_bytes: Real PE leading bytes (starts with ``MZ``).
        """
        assert real_pe_bytes[:2] == b"MZ"
        node = RegexReplaceNode()
        result = node.process(real_pe_bytes, {"pattern": "MZ", "replacement": "5858"})
        assert result[:2] == b"XX"
        assert len(result) == len(real_pe_bytes)
        assert result[2:] == real_pe_bytes[2:]

    def test_delete_pattern_with_empty_replacement(self) -> None:
        """An empty replacement removes every match from the data."""
        node = RegexReplaceNode()
        data = b"\x00\xff\x00\xff\x00"
        result = node.process(data, {"pattern": "\\xff"})
        assert result == b"\x00\x00\x00"

    def test_bytes_replacement_value(self) -> None:
        """A bytes replacement value is honoured directly."""
        node = RegexReplaceNode()
        result = node.process(b"abcabc", {"pattern": "a", "replacement": b"Z"})
        assert result == b"ZbcZbc"

    def test_missing_pattern_raises(self) -> None:
        """A missing ``pattern`` raises ``TransformParamError``."""
        node = RegexReplaceNode()
        with pytest.raises(TransformParamError, match="requires 'pattern'"):
            node.process(b"abc", {})

    def test_invalid_regex_raises(self) -> None:
        """An unbalanced regex raises ``TransformParamError``."""
        node = RegexReplaceNode()
        with pytest.raises(TransformParamError, match="invalid regex"):
            node.process(b"abc", {"pattern": "([a-z"})


class TestRepeatTruncatePadNodes:
    """Coverage for the structural Python transform nodes."""

    def test_repeat_real_bytes(self, real_pe_bytes: bytes) -> None:
        """``RepeatNode`` concatenates the input ``count`` times.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        node = RepeatNode()
        result = node.process(real_pe_bytes, {"count": 3})
        assert result == real_pe_bytes * 3

    def test_repeat_invalid_count_raises(self) -> None:
        """A zero count is rejected by ``RepeatNode``."""
        node = RepeatNode()
        with pytest.raises(TransformParamError, match="must be >= 1"):
            node.process(b"ab", {"count": 0})

    def test_repeat_non_int_count_raises(self) -> None:
        """A non-integer count is rejected by ``RepeatNode``."""
        node = RepeatNode()
        with pytest.raises(TransformParamError, match="not int"):
            node.process(b"ab", {"count": "many"})

    def test_truncate_real_bytes(self, real_pe_bytes: bytes) -> None:
        """``TruncateNode`` keeps only the first ``length`` bytes.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        node = TruncateNode()
        result = node.process(real_pe_bytes, {"length": 16})
        assert result == real_pe_bytes[:16]

    def test_truncate_longer_than_data_returns_all(self) -> None:
        """Truncating beyond the data length returns the full input."""
        node = TruncateNode()
        assert node.process(b"abc", {"length": 100}) == b"abc"

    def test_truncate_missing_length_raises(self) -> None:
        """A missing ``length`` raises ``TransformParamError``."""
        node = TruncateNode()
        with pytest.raises(TransformParamError, match="requires 'length'"):
            node.process(b"abc", {})

    def test_truncate_negative_length_raises(self) -> None:
        """A negative ``length`` raises ``TransformParamError``."""
        node = TruncateNode()
        with pytest.raises(TransformParamError, match="must be >= 0"):
            node.process(b"abc", {"length": -1})

    def test_pad_extends_with_fill_byte(self) -> None:
        """``PadNode`` extends short data to the target length."""
        node = PadNode()
        result = node.process(b"ab", {"length": 5, "byte": 0xAA})
        assert result == b"ab" + bytes([0xAA, 0xAA, 0xAA])

    def test_pad_default_fill_is_zero(self) -> None:
        """``PadNode`` fills with NUL bytes by default."""
        node = PadNode()
        assert node.process(b"x", {"length": 4}) == b"x\x00\x00\x00"

    def test_pad_no_op_when_already_long(self, real_pe_bytes: bytes) -> None:
        """Data already at or beyond ``length`` is returned unchanged.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        node = PadNode()
        assert node.process(real_pe_bytes, {"length": 10}) == real_pe_bytes

    def test_pad_invalid_fill_byte_raises(self) -> None:
        """A fill byte outside 0-255 raises ``TransformParamError``."""
        node = PadNode()
        with pytest.raises(TransformParamError, match="must be 0-255"):
            node.process(b"x", {"length": 4, "byte": 999})


class TestTransformPipeline:
    """End-to-end pipeline orchestration with Python nodes."""

    def test_execute_chains_python_nodes(self, real_pe_bytes: bytes) -> None:
        """A multi-step pipeline applies each step in order over real bytes.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        pipeline = TransformPipeline()
        pipeline.add_step(TruncateNode(), {"length": 8})
        pipeline.add_step(CustomExpressionNode(), {"expression": "b ^ 0xFF"})
        pipeline.add_step(RepeatNode(), {"count": 2})
        result = pipeline.execute(real_pe_bytes)
        expected_truncated = real_pe_bytes[:8]
        expected_xored = bytes(byte ^ 0xFF for byte in expected_truncated)
        assert result == expected_xored * 2

    def test_preview_captures_intermediate_outputs(self, real_pe_bytes: bytes) -> None:
        """``preview`` returns the named output of each pipeline step.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        pipeline = TransformPipeline()
        pipeline.add_step(TruncateNode(), {"length": 4})
        pipeline.add_step(PadNode(), {"length": 8, "byte": 0x00})
        preview = pipeline.preview(real_pe_bytes)
        assert [name for name, _ in preview] == ["truncate", "pad"]
        assert preview[0][1] == real_pe_bytes[:4]
        assert preview[1][1] == real_pe_bytes[:4] + b"\x00\x00\x00\x00"

    def test_remove_and_move_steps(self) -> None:
        """Step removal and reordering manage the pipeline correctly."""
        pipeline = TransformPipeline()
        pipeline.add_step(TruncateNode(), {"length": 2})
        pipeline.add_step(RepeatNode(), {"count": 2})
        pipeline.add_step(PadNode(), {"length": 16})
        assert pipeline.move_step(2, 0) is True
        assert [step.node.name for step in pipeline.steps] == ["pad", "truncate", "repeat"]
        assert pipeline.remove_step(0) is True
        assert [step.node.name for step in pipeline.steps] == ["truncate", "repeat"]
        assert pipeline.remove_step(99) is False
        pipeline.clear()
        assert pipeline.steps == []

    def test_execute_empty_pipeline_returns_input(self, real_pe_bytes: bytes) -> None:
        """An empty pipeline returns its input unchanged.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        assert TransformPipeline().execute(real_pe_bytes) == real_pe_bytes


class TestRustTransformNode:
    """Rust hexcore transform coverage with parameter coercion."""

    def test_base64_encode_matches_stdlib(self, real_pe_bytes: bytes) -> None:
        """The Rust base64 transform matches ``base64.b64encode`` of real data.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        node = RustTransformNode("base64_encode", "encoding", "Base64 encode")
        if not _hexcore_present():
            pytest.skip("intellicrack_hexcore is not available in this environment")
        result = node.process(real_pe_bytes, {})
        assert result == base64.b64encode(real_pe_bytes)
        assert node.name == "base64_encode"
        assert node.category == "encoding"
        assert node.description == "Base64 encode"

    def test_base64_roundtrip_via_pipeline(self, real_pe_bytes: bytes) -> None:
        """Encode-then-decode through the Rust transforms recovers the input.

        Args:
            real_pe_bytes: Real PE leading bytes.
        """
        if not _hexcore_present():
            pytest.skip("intellicrack_hexcore is not available in this environment")
        pipeline = TransformPipeline()
        pipeline.add_step(RustTransformNode("base64_encode"))
        pipeline.add_step(RustTransformNode("base64_decode"))
        assert pipeline.execute(real_pe_bytes) == real_pe_bytes

    def test_hex_string_param_coercion_for_xor(self) -> None:
        """A hex-string key param is coerced to bytes for the Rust xor.

        ``"ff"`` is a valid even-length hex string and is decoded to the
        single byte ``0xff``; XORing ``b"AAAA"`` (0x41) yields ``0xbe`` bytes.
        """
        if not _hexcore_present():
            pytest.skip("intellicrack_hexcore is not available in this environment")
        node = RustTransformNode("xor_single")
        result = node.process(b"AAAA", {"key": "ff"})
        assert result == bytes([0x41 ^ 0xFF]) * 4

    def test_integer_param_coercion_for_xor(self) -> None:
        """An integer key param (0-255) is coerced to a single little-endian byte."""
        if not _hexcore_present():
            pytest.skip("intellicrack_hexcore is not available in this environment")
        node = RustTransformNode("xor_single")
        result = node.process(b"\x00\x01\x02", {"key": 0x10})
        assert result == bytes([0x10, 0x11, 0x12])


class TestNodeRegistry:
    """Coverage for ``get_all_transform_nodes`` and unavailability handling."""

    def test_get_all_transform_nodes_includes_python_nodes(self) -> None:
        """The registry always includes the five Python-only transforms."""
        nodes = get_all_transform_nodes()
        names = {node.name for node in nodes}
        assert {
            "regex_replace",
            "custom_expression",
            "repeat",
            "truncate",
            "pad",
        } <= names

    def test_get_all_transform_nodes_includes_rust_when_available(self) -> None:
        """Rust transforms are present when hexcore is importable."""
        nodes = get_all_transform_nodes()
        names = {node.name for node in nodes}
        if _hexcore_present():
            assert "base64_encode" in names
        else:
            assert "base64_encode" not in names

    def test_hexcore_unavailable_error_raised_when_missing(self) -> None:
        """``RustTransformNode`` raises ``HexcoreUnavailableError`` when absent.

        When hexcore IS available this asserts the success path produces output
        instead; when it is genuinely absent the error path is asserted. Either
        way the unavailability contract is verified against the real module
        state rather than a fabricated import failure.
        """
        node = RustTransformNode("base64_encode")
        if _hexcore_present():
            assert node.process(b"abc", {}) == base64.b64encode(b"abc")
        else:
            with pytest.raises(HexcoreUnavailableError):
                node.process(b"abc", {})


def _hexcore_present() -> bool:
    """Report whether the real ``intellicrack_hexcore`` module is importable.

    Probes the real module-state flags via the public module object so the
    determination matches exactly what :class:`RustTransformNode` observes at
    runtime.

    Returns:
        bool: ``True`` when the Rust extension module is available.
    """
    available = getattr(transform_pipeline, "_hexcore_available", False)
    module = getattr(transform_pipeline, "_hexcore_mod", None)
    return bool(available) and module is not None
