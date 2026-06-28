# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Real-gate tests for TransformPipeline nodes (Group 06 Wave 5).

Covers:
  S7-13 — ``TransformPipeline`` mid-pipeline step error propagation: a step-2
           ``TransformParamError`` propagates; not silently swallowed.
  S7-14 — ``TransformPipeline.to_dict`` / ``from_dict`` (UNTESTABLE: methods
           do not exist in the production class).
  S7-18 — ``RustTransformNode`` param coercion: non-hex even-length string
           param must raise ``TransformParamError`` (PD-010 RED-BY-DESIGN).
  S7-19 — ``RegexReplaceNode`` with ``str`` type replacement: hex-string param
           ``"41"`` is correctly converted to ``b"\x41"`` (= ``b"A"``).
"""
from __future__ import annotations

import pytest

from intellicrack.core.transform_pipeline import (
    HexcoreUnavailableError,
    RegexReplaceNode,
    RepeatNode,
    RustTransformNode,
    TransformParamError,
    TransformPipeline,
)


class TestTransformPipelineMidStepError:
    """Gate for S7-13: TransformParamError from step 2 propagates through execute()."""

    def test_step_two_error_propagates(self) -> None:
        """TransformParamError from step 2 is not caught by the pipeline execute loop.

        Oracle: ``TransformPipeline.execute`` iterates steps with no try/except,
        so any ``TransformParamError`` from an inner node reaches the caller
        unchanged.  The RepeatNode raises ``TransformParamError`` when count < 1
        (verified against ``_NODE_REPEAT`` detail in the source).

        Mutation: wrapping the inner loop in ``try/except TransformParamError``
        and returning the step-1 result silently would make the function return
        a value instead of raising, causing ``pytest.raises`` to report
        DID NOT RAISE.
        """
        pipeline = TransformPipeline()
        pipeline.add_step(RepeatNode(), params={"count": 1})
        pipeline.add_step(RepeatNode(), params={"count": 0})

        with pytest.raises(TransformParamError, match=r"'count' must be >= 1"):
            pipeline.execute(b"\x4d\x5a\x90\x00")

    def test_step_one_output_not_silently_returned_on_step_two_error(self) -> None:
        r"""Step-1 output is not returned when step-2 raises.

        Oracle: if the pipeline correctly propagates the error, no result is
        returned from ``execute``.  Mutation: returning step-1 output instead of
        re-raising would mean ``execute(b"\x4d")`` returns ``b"\x4d\x4d"``
        (repeat-2 result) rather than raising — the ``pytest.raises`` block
        would then NOT raise.
        """
        pipeline = TransformPipeline()
        pipeline.add_step(RepeatNode(), params={"count": 2})
        pipeline.add_step(RepeatNode(), params={"count": -1})

        with pytest.raises(TransformParamError):
            pipeline.execute(b"\x4d")

    def test_error_from_first_step_also_propagates(self) -> None:
        """TransformParamError from step 1 propagates identically.

        Oracle: same no-except loop; the first step raising means no
        subsequent step runs.  Mutation: silently swallowing any step error
        would cause ``execute`` to return the unchanged input bytes, not raise.
        """
        pipeline = TransformPipeline()
        pipeline.add_step(RepeatNode(), params={"count": 0})

        with pytest.raises(TransformParamError, match=r"'count' must be >= 1"):
            pipeline.execute(b"\xff\xfe\x00\x00")


class TestTransformPipelineSerializationUntestable:
    """S7-14: to_dict / from_dict absent — methods do not exist on TransformPipeline."""

    def test_to_dict_absent_from_production_class(self) -> None:
        """Confirm TransformPipeline has no to_dict method (S7-14 UNTESTABLE).

        S7-14 requests serialization round-trip tests, but ``to_dict`` and
        ``from_dict`` are not present in the production class.  This gate
        documents the absence so the finding is tracked rather than silently
        ignored.  When the methods are added, this test turns red and must be
        replaced with a real round-trip gate.
        """
        pipeline = TransformPipeline()
        assert not hasattr(pipeline, "to_dict"), (
            "TransformPipeline.to_dict now exists — replace this placeholder with "
            "a real serialization round-trip gate for S7-14."
        )

    def test_from_dict_absent_from_production_class(self) -> None:
        """Confirm TransformPipeline has no from_dict class method (S7-14 UNTESTABLE).

        See ``test_to_dict_absent_from_production_class`` for context.
        """
        assert not hasattr(TransformPipeline, "from_dict"), (
            "TransformPipeline.from_dict now exists — replace this placeholder with "
            "a real deserialization gate for S7-14."
        )


class TestRustTransformNodeInvalidParams:
    """Gate for S7-18: RustTransformNode raises TransformParamError for invalid params.

    PD-010 RED-BY-DESIGN.

    The production code (transform_pipeline.py ~L340) silently UTF-8 encodes
    a non-hex even-length string param instead of raising ``TransformParamError``.
    The correct contract (asserted here) is that an even-length string that is
    not valid hex must be rejected with ``TransformParamError``.

    ``xor_repeating`` is used as the target transform: it is registered in
    the Rust hexcore (transforms.rs, TRANSFORM_LIST), accepts any non-empty
    ``key`` bytes, and is available in the ``xor`` category.  Passing a
    non-hex string ``"GG"`` (``G`` is not a hexdigit) as ``key`` is the
    precise input that exercises the PD-010 coercion bug.
    """

    def test_non_hex_even_length_string_raises_transform_param_error(self) -> None:
        """Non-hex even-length string param must raise TransformParamError.

        This test is RED-BY-DESIGN (PD-010): the production code checks
        ``is_hex = len(val) > 0 and len(val) % 2 == 0 and all(c in hexdigits …)``
        for string params.  ``"GG"`` is even-length but ``G ∉ hexdigits``, so
        ``is_hex`` is False and the code silently does ``val.encode('utf-8')``
        → ``b"GG"`` (a valid 2-byte key for ``xor_repeating``), rather than
        raising ``TransformParamError``.  Oracle: the correct contract is to
        reject any string that cannot be decoded as hex.  Mutation: adding the
        ``if not is_hex: raise TransformParamError(...)`` branch turns this gate
        green.

        The test skips if hexcore is unavailable in the test environment
        (``HexcoreUnavailableError`` is the expected exception when hexcore is
        absent, not ``TransformParamError``).
        """
        node = RustTransformNode("xor_repeating", transform_category="xor")
        try:
            node.process(b"\x00\x01\x02\x03", {"key": "GG"})
        except HexcoreUnavailableError:
            pytest.skip("intellicrack_hexcore not built in this environment")
        except TransformParamError:
            return

        pytest.fail(
            "PD-010: RustTransformNode silently UTF-8 encoded the non-hex param 'GG' "
            "instead of raising TransformParamError.",
        )

    def test_odd_length_string_raises_transform_param_error(self) -> None:
        """Odd-length string param must raise TransformParamError.

        Oracle: odd-length strings cannot be valid hex (hex encodes bytes, each
        byte needing 2 hex digits), so the node must reject them.  The production
        code checks ``len(val) % 2 == 0`` as part of ``is_hex``; an odd-length
        string like ``"A"`` fails that check so ``is_hex`` is False and the code
        reaches ``val.encode('utf-8')`` → ``b"A"`` (a valid 1-byte key for
        ``xor_repeating``), making this also RED-BY-DESIGN (PD-010).  Skips if
        hexcore is absent.
        """
        node = RustTransformNode("xor_repeating", transform_category="xor")
        try:
            node.process(b"\x00", {"key": "A"})
        except HexcoreUnavailableError:
            pytest.skip("intellicrack_hexcore not built in this environment")
        except TransformParamError:
            return

        pytest.fail(
            "PD-010: RustTransformNode did not raise TransformParamError for odd-length "
            "non-hex string param 'A'.",
        )


class TestRegexReplaceNodeStrReplacement:
    """Gate for S7-19: RegexReplaceNode correctly handles str type replacement."""

    def test_hex_str_replacement_converts_to_bytes(self) -> None:
        r"""Hex string replacement '41' is converted to b'\x41' (= b'A').

        Oracle: ``bytes.fromhex('41') == b'\x41' == b'A'``.  The production
        code (transform_pipeline.py ~L412) performs
        ``replacement = bytes.fromhex(raw_replacement)`` for non-empty strings.
        Mutation: skipping the ``isinstance(raw_replacement, str)`` branch and
        treating the string as bytes directly would substitute the literal
        ASCII text ``b'41'`` at the match site, not the decoded byte ``b'A'``.
        """
        data = b"MZ\x00\x00\x00\x00"
        node = RegexReplaceNode()
        result = node.process(data, {"pattern": "MZ", "replacement": "41"})
        assert result == b"A\x00\x00\x00\x00", (
            f"Expected MZ→A via hex '41'→b'\\x41'; got {result!r}"
        )

    def test_empty_str_replacement_replaces_with_empty_bytes(self) -> None:
        """Empty string replacement '' replaces the match with empty bytes.

        Oracle: ``bytes.fromhex('') if raw_replacement else b''`` — an empty
        string guard ensures the empty-replacement case returns ``b''``.
        Mutation: treating empty string as bytes literal ``b''`` accidentally
        works for ASCII but would fail if the guard is removed and
        ``bytes.fromhex('')`` is called unconditionally (which is fine — but
        removing the guard entirely and returning the str itself would produce
        ``b''`` only by coincidence).  This test confirms the bytes result.
        """
        data = b"MZ\x90\x00"
        node = RegexReplaceNode()
        result = node.process(data, {"pattern": "MZ", "replacement": ""})
        assert result == b"\x90\x00", (
            f"Expected MZ deleted (replaced with empty); got {result!r}"
        )

    def test_multi_byte_hex_str_replacement(self) -> None:
        r"""Multi-byte hex string replacement '4d5a' converts to b'MZ'.

        Oracle: ``bytes.fromhex('4d5a') == b'MZ'``.  Substituting 'MZ' over a
        pattern that matched '\x00\x00' verifies multi-byte decode.  Mutation:
        treating '4d5a' as a raw string literal for the replacement would produce
        the ASCII bytes of "4d5a" rather than the two decoded bytes.
        """
        data = b"\x00\x00\x90\x00"
        node = RegexReplaceNode()
        result = node.process(data, {"pattern": r"\x00\x00", "replacement": "4d5a"})
        assert result == b"MZ\x90\x00", (
            f"Expected '\\x00\\x00'→b'MZ' via hex '4d5a'; got {result!r}"
        )

    def test_bytes_replacement_used_directly(self) -> None:
        """Bytes replacement is used without conversion.

        Oracle: when replacement is already ``bytes``, the production code takes
        ``replacement = raw_replacement`` directly (not ``bytes.fromhex``).
        Mutation: always calling ``bytes.fromhex(raw_replacement)`` regardless of
        type raises ``AttributeError`` on bytes objects (no ``fromhex`` on bytes),
        making this assertion unreachable.
        """
        data = b"MZ\x90\x00"
        node = RegexReplaceNode()
        result = node.process(data, {"pattern": "MZ", "replacement": b"\x4e\x45"})
        assert result == b"NE\x90\x00", (
            f"Expected direct bytes replacement b'\\x4e\\x45' = b'NE'; got {result!r}"
        )
