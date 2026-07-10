# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-gate tests for local-model classification helpers (wave 2d).

Fixes FG-12 (list_models any-substring weakness) by pinning every
RECOMMENDED_MODELS_B580 entry and verifies three previously un-tested
pure helpers against independent oracles:

* ``_classify_model_capabilities`` -- context-window key priority order
  (max_position_embeddings > max_sequence_length > n_positions), vision
  keyword detection via architectures list, vision_config / image_size
  fallback, and empty-config default.  Independent oracle: published
  HuggingFace model-card config shapes and the documented priority table.
* ``_strip_pwsh_payload`` -- BOM (U+FEFF) stripping and whitespace
  normalisation.  Independent oracle: Unicode spec U+FEFF and documented
  PowerShell UTF-8-with-BOM behaviour on Windows.
* ``_estimate_memory_from_name`` -- device-name-to-VRAM mapping for every
  Intel Arc SKU branch plus the unknown-device fallback.  Independent
  oracle: Intel published Arc product-line VRAM specifications.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.providers import (
    local_transformers as _lt_mod,
    xpu_utils as _xpu_mod,
)
from intellicrack.providers.model_loader import RECOMMENDED_MODELS_B580


if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------------------------------------------------------
# Module-level typed wrappers for private helpers (avoids reportPrivateUsage)
# ---------------------------------------------------------------------------


def _classify_model_capabilities(config: dict[str, Any]) -> tuple[int, bool]:
    """Invoke local_transformers._classify_model_capabilities via vars().

    Args:
        config: Parsed HuggingFace config.json dict to classify.

    Returns:
        tuple[int, bool]: (context_window, supports_vision) from the
        production function.
    """
    fn = cast(
        "Callable[[dict[str, Any]], tuple[int, bool]]",
        vars(_lt_mod)["_classify_model_capabilities"],
    )
    return fn(config)


def _strip_pwsh_payload(stdout: str) -> str:
    """Invoke xpu_utils._strip_pwsh_payload via vars().

    Args:
        stdout: Raw PowerShell stdout text to strip.

    Returns:
        str: Payload with BOM and surrounding whitespace removed.
    """
    fn = cast(
        "Callable[[str], str]",
        vars(_xpu_mod)["_strip_pwsh_payload"],
    )
    return fn(stdout)


def _estimate_memory_from_name(device_name: str) -> int:
    """Invoke xpu_utils._estimate_memory_from_name via vars().

    Args:
        device_name: Device name string from WMI or torch.

    Returns:
        int: Estimated device memory in bytes.
    """
    fn = cast(
        "Callable[[str], int]",
        vars(_xpu_mod)["_estimate_memory_from_name"],
    )
    return fn(device_name)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_1_GiB: int = 1024 * 1024 * 1024
_DEFAULT_CTX: int = 4096

_BOM: str = "﻿"

_EXPECTED_MODEL_IDS: tuple[str, ...] = (
    "microsoft/Phi-3-mini-4k-instruct",
    "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
    "Qwen/Qwen2.5-1.5B-Instruct",
    "Qwen/Qwen2.5-3B-Instruct",
    "meta-llama/Llama-3.2-1B-Instruct",
    "meta-llama/Llama-3.2-3B-Instruct",
    "mistralai/Mistral-7B-Instruct-v0.3",
)


# ---------------------------------------------------------------------------
# FG-12 -- RECOMMENDED_MODELS_B580 exact entry pinning
# ---------------------------------------------------------------------------


class TestRecommendedModelsB580:
    """Pin all seven RECOMMENDED_MODELS_B580 entries by exact model_id.

    The pre-existing test only checked any("phi" or "tiny") in model IDs;
    a single model named "phi-placeholder" would have passed.  These gates
    require every specific entry to be present with its full field set.
    """

    @staticmethod
    def test_exact_entry_count() -> None:
        """Exactly seven entries must be present in the constant."""
        assert len(RECOMMENDED_MODELS_B580) == 7

    @pytest.mark.parametrize("expected_id", _EXPECTED_MODEL_IDS)
    def test_each_model_id_present(self, expected_id: str) -> None:
        """Each expected model_id must appear in RECOMMENDED_MODELS_B580.

        A mutation dropping any single entry (or changing its ID) would
        cause the corresponding parametrize row to fail.

        Args:
            expected_id: Exact model identifier that must be present.
        """
        present_ids = {str(entry["model_id"]) for entry in RECOMMENDED_MODELS_B580}
        assert expected_id in present_ids

    @pytest.mark.parametrize("expected_id", _EXPECTED_MODEL_IDS)
    def test_each_entry_has_required_fields(self, expected_id: str) -> None:
        """Every RECOMMENDED_MODELS_B580 entry must carry all four structural fields.

        Args:
            expected_id: Model identifier whose entry is checked for field completeness.
        """
        matching = [e for e in RECOMMENDED_MODELS_B580 if str(e["model_id"]) == expected_id]
        assert matching, f"No entry found for {expected_id!r}"
        entry = matching[0]
        assert "description" in entry
        assert "recommended_dtype" in entry
        assert "estimated_memory_gb" in entry
        assert isinstance(entry["recommended_dtype"], str)
        assert isinstance(entry["estimated_memory_gb"], float)

    @staticmethod
    def test_mistral_7b_uses_int8_dtype() -> None:
        """Mistral-7B must specify int8 so it fits within 12 GB VRAM."""
        entries = [e for e in RECOMMENDED_MODELS_B580 if str(e["model_id"]) == "mistralai/Mistral-7B-Instruct-v0.3"]
        assert entries, "Mistral entry is missing"
        assert str(entries[0]["recommended_dtype"]) == "int8"

    @staticmethod
    def test_tinyllama_uses_float16() -> None:
        """TinyLlama must use float16, not a quantized dtype."""
        entries = [e for e in RECOMMENDED_MODELS_B580 if str(e["model_id"]) == "TinyLlama/TinyLlama-1.1B-Chat-v1.0"]
        assert entries, "TinyLlama entry is missing"
        assert str(entries[0]["recommended_dtype"]) == "float16"

    @staticmethod
    def test_phi3_mini_memory_is_below_12gb() -> None:
        """Phi-3-mini-4k estimated memory must fit within 12 GB B580 VRAM."""
        entries = [e for e in RECOMMENDED_MODELS_B580 if str(e["model_id"]) == "microsoft/Phi-3-mini-4k-instruct"]
        assert entries, "Phi-3-mini entry is missing"
        memory_gb = float(str(entries[0]["estimated_memory_gb"]))
        assert memory_gb < 12.0, f"Phi-3-mini estimated memory {memory_gb} GB exceeds B580 VRAM"


# ---------------------------------------------------------------------------
# _classify_model_capabilities -- context-window extraction
# ---------------------------------------------------------------------------


class TestClassifyContextWindow:
    """Gate _classify_model_capabilities context-window key priority logic."""

    @staticmethod
    def test_empty_config_returns_default_4096() -> None:
        """An empty config must return the documented 4096 fallback context window."""
        ctx, _ = _classify_model_capabilities({})
        assert ctx == _DEFAULT_CTX

    @staticmethod
    def test_max_position_embeddings_used_for_phi3_mini() -> None:
        """max_position_embeddings must be returned unchanged.

        Independent oracle: microsoft/Phi-3-mini-4k-instruct publishes
        max_position_embeddings=4096 in its config.json on HuggingFace Hub.
        """
        config: dict[str, Any] = {
            "max_position_embeddings": 4096,
            "architectures": ["Phi3ForCausalLM"],
        }
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == 4096

    @staticmethod
    def test_large_max_position_embeddings_not_capped() -> None:
        """max_position_embeddings=32768 must pass through without capping.

        Independent oracle: Mistral-7B-Instruct config.json lists
        max_position_embeddings=32768 on HuggingFace Hub.
        """
        config: dict[str, Any] = {"max_position_embeddings": 32768}
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == 32768

    @staticmethod
    def test_max_sequence_length_used_when_no_max_position() -> None:
        """max_sequence_length must be used when max_position_embeddings is absent."""
        config: dict[str, Any] = {"max_sequence_length": 2048}
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == 2048

    @staticmethod
    def test_n_positions_used_when_higher_priority_keys_absent() -> None:
        """n_positions must be used when both higher-priority keys are absent.

        Independent oracle: GPT-2 config.json lists n_positions=1024 on
        HuggingFace Hub; this key is the primary context indicator for
        GPT-2-family models.
        """
        config: dict[str, Any] = {"n_positions": 1024}
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == 1024

    @staticmethod
    def test_max_position_embeddings_wins_over_max_sequence_length() -> None:
        """max_position_embeddings must win when both keys co-exist.

        Mutation oracle: swapping the priority order would return 2048
        instead of 8192 for this config.
        """
        config: dict[str, Any] = {
            "max_position_embeddings": 8192,
            "max_sequence_length": 2048,
        }
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == 8192

    @staticmethod
    def test_max_sequence_length_wins_over_n_positions() -> None:
        """max_sequence_length must win when n_positions is also present.

        Mutation oracle: swapping the second and third priority positions
        would return 1024 instead of 4096 for this config.
        """
        config: dict[str, Any] = {
            "max_sequence_length": 4096,
            "n_positions": 1024,
        }
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == 4096

    @staticmethod
    def test_all_three_keys_max_position_dominates() -> None:
        """With all three context-window keys present, max_position_embeddings dominates."""
        config: dict[str, Any] = {
            "max_position_embeddings": 16384,
            "max_sequence_length": 8192,
            "n_positions": 1024,
        }
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == 16384

    @staticmethod
    def test_zero_value_skipped_falls_through_to_default() -> None:
        """A zero context-window value must be ignored; the fallback 4096 is returned."""
        config: dict[str, Any] = {"max_position_embeddings": 0}
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == _DEFAULT_CTX

    @staticmethod
    def test_negative_value_skipped_falls_through_to_default() -> None:
        """A negative context-window value must be ignored; the fallback is returned."""
        config: dict[str, Any] = {"max_position_embeddings": -1}
        ctx, _ = _classify_model_capabilities(config)
        assert ctx == _DEFAULT_CTX


# ---------------------------------------------------------------------------
# _classify_model_capabilities -- vision detection
# ---------------------------------------------------------------------------


class TestClassifyVisionSupport:
    """Gate _classify_model_capabilities vision-capability detection."""

    @staticmethod
    def test_empty_config_returns_false_vision() -> None:
        """An empty config must default to supports_vision=False."""
        _, vision = _classify_model_capabilities({})
        assert vision is False

    @staticmethod
    def test_non_vision_causal_lm_returns_false() -> None:
        """A causal-LM-only architecture must not be flagged as vision-capable.

        Independent oracle: Phi-3-mini uses Phi3ForCausalLM; none of the
        vision keywords (vision, vit, clip, llava, visual, image) appear in
        that architecture name when lower-cased.
        """
        config: dict[str, Any] = {
            "architectures": ["Phi3ForCausalLM"],
            "max_position_embeddings": 4096,
        }
        _, vision = _classify_model_capabilities(config)
        assert vision is False

    @pytest.mark.parametrize(
        ("arch_name", "matched_keyword"),
        [
            ("LlavaForConditionalGeneration", "llava"),
            ("LlavaNextForConditionalGeneration", "llava"),
            ("ViTForImageClassification", "vit"),
            ("CLIPModel", "clip"),
            ("VisionEncoderDecoderModel", "vision"),
            ("VisualBertModel", "visual"),
            ("ImageGPTForCausalImageModeling", "image"),
        ],
    )
    def test_vision_keyword_in_architecture_name(
        self,
        arch_name: str,
        matched_keyword: str,
    ) -> None:
        """Vision keyword in architectures list must set supports_vision=True.

        Independent oracle: These architecture class names are published in
        HuggingFace model cards and the Transformers library docs; the
        expected keyword appears literally in the lowercased arch name.

        Args:
            arch_name: Architecture class name string from config.json.
            matched_keyword: The vision keyword that must appear in arch_name.lower().
        """
        assert matched_keyword in arch_name.lower(), f"Test construction error: {matched_keyword!r} not in {arch_name!r}"
        config: dict[str, Any] = {
            "architectures": [arch_name],
            "max_position_embeddings": 4096,
        }
        _, vision = _classify_model_capabilities(config)
        assert vision is True

    @staticmethod
    def test_vision_config_key_triggers_vision() -> None:
        """Presence of vision_config key must set supports_vision=True.

        Independent oracle: LLaVA and IDEFICS models publish a nested
        vision_config block in their config.json alongside text-model fields.
        """
        config: dict[str, Any] = {
            "max_sequence_length": 2048,
            "vision_config": {"image_size": 336},
        }
        _, vision = _classify_model_capabilities(config)
        assert vision is True

    @staticmethod
    def test_image_size_key_triggers_vision() -> None:
        """Presence of a top-level image_size key must set supports_vision=True."""
        config: dict[str, Any] = {
            "max_position_embeddings": 2048,
            "image_size": 224,
        }
        _, vision = _classify_model_capabilities(config)
        assert vision is True

    @staticmethod
    def test_empty_architectures_list_returns_false() -> None:
        """An empty architectures list must not trigger vision detection."""
        config: dict[str, Any] = {"architectures": []}
        _, vision = _classify_model_capabilities(config)
        assert vision is False

    @staticmethod
    def test_mistral_causal_lm_non_vision_large_context() -> None:
        """Mistral-7B config must yield (32768, False).

        Independent oracle: Mistral-7B-Instruct-v0.3 config.json lists
        max_position_embeddings=32768 and architectures=['MistralForCausalLM'].
        """
        config: dict[str, Any] = {
            "max_position_embeddings": 32768,
            "architectures": ["MistralForCausalLM"],
        }
        ctx, vision = _classify_model_capabilities(config)
        assert ctx == 32768
        assert vision is False

    @staticmethod
    def test_llava_vision_arch_and_context_window() -> None:
        """A LLaVA config must yield (4096, True).

        Independent oracle: llava-hf/llava-1.5-7b-hf config.json lists
        max_position_embeddings=4096 and architectures containing
        LlavaForConditionalGeneration.
        """
        config: dict[str, Any] = {
            "max_position_embeddings": 4096,
            "architectures": ["LlavaForConditionalGeneration"],
        }
        ctx, vision = _classify_model_capabilities(config)
        assert ctx == 4096
        assert vision is True


# ---------------------------------------------------------------------------
# _strip_pwsh_payload -- BOM removal and whitespace normalization
# ---------------------------------------------------------------------------


class TestStripPwshPayload:
    """Gate _strip_pwsh_payload against the Unicode BOM spec.

    The BOM constant _BOM is U+FEFF (Unicode Byte Order Mark), whose
    UTF-8 encoding is the three-byte sequence 0xEF 0xBB 0xBF.
    PowerShell on Windows emits UTF-8 with BOM by default.
    """

    @staticmethod
    def test_bom_prefix_removed_leaving_bare_json() -> None:
        """U+FEFF at the start of the payload must be stripped.

        Independent oracle: Unicode spec -- U+FEFF is the Byte Order Mark;
        PowerShell on Windows emits UTF-8 with BOM by default unless
        OutputEncoding is overridden.
        """
        raw = _BOM + '{"key": 1}'
        result = _strip_pwsh_payload(raw)
        assert result == '{"key": 1}'

    @staticmethod
    def test_bom_and_surrounding_whitespace_both_removed() -> None:
        """BOM prefix plus whitespace padding must all be stripped."""
        raw = f"{_BOM}  " + '{"key": 1}' + "\n  "
        result = _strip_pwsh_payload(raw)
        assert result == '{"key": 1}'

    @staticmethod
    def test_no_bom_whitespace_still_stripped() -> None:
        """Without a BOM, surrounding whitespace must still be removed."""
        raw = "  " + '{"key": 2}' + "  "
        result = _strip_pwsh_payload(raw)
        assert result == '{"key": 2}'

    @staticmethod
    def test_bom_only_input_returns_empty_string() -> None:
        """BOM followed by only whitespace must produce an empty string."""
        raw = _BOM + "\n\r\n"
        result = _strip_pwsh_payload(raw)
        assert not result

    @staticmethod
    def test_empty_string_input_returns_empty_string() -> None:
        """An empty input string must return an empty string."""
        result = _strip_pwsh_payload("")
        assert not result

    @staticmethod
    def test_multiple_leading_boms_all_stripped() -> None:
        """Multiple consecutive BOM characters at the start must all be removed.

        str.lstrip() strips all leading occurrences of characters in its
        argument, so two or more consecutive BOMs are removed completely.
        """
        raw = _BOM + _BOM + '{"data": true}'
        result = _strip_pwsh_payload(raw)
        assert result == '{"data": true}'

    @staticmethod
    def test_mid_string_bom_is_preserved() -> None:
        """A BOM embedded in the middle of a string must not be removed.

        Only the leading BOM characters are stripped by lstrip; interior
        occurrences are left in place by both lstrip and strip.
        """
        mid_bom = '{"key": "' + _BOM + '"}'
        result = _strip_pwsh_payload(mid_bom)
        assert result == mid_bom

    @staticmethod
    def test_real_powershell_gpu_json_array_with_bom() -> None:
        """A realistic PowerShell GPU JSON array preceded by BOM is cleaned correctly."""
        raw = _BOM + '[{"Name":"Intel Arc B580","PNPDeviceID":' + '"PCI\\\\VEN_8086&DEV_E20B","DriverVersion":"31.0.101.5522"}]'
        result = _strip_pwsh_payload(raw)
        assert result.startswith("[{")
        assert _BOM not in result

    @staticmethod
    def test_stripped_result_is_valid_json() -> None:
        """After stripping, the result must be parseable by json.loads."""
        raw = f"{_BOM}  " + '{"gpu": "Intel Arc B580", "vram_gb": 12}' + "\n"
        result = _strip_pwsh_payload(raw)
        parsed: dict[str, object] = json.loads(result)
        assert parsed["gpu"] == "Intel Arc B580"
        assert parsed["vram_gb"] == 12


# ---------------------------------------------------------------------------
# _estimate_memory_from_name -- VRAM constant table
# ---------------------------------------------------------------------------

_VRAM_TABLE: tuple[tuple[str, int], ...] = (
    ("Intel Arc B580", 12 * _1_GiB),
    ("intel arc b580 graphics", 12 * _1_GiB),
    ("Intel Arc A770", 16 * _1_GiB),
    ("Intel(R) Arc(TM) A770 Graphics", 16 * _1_GiB),
    ("Intel Arc A750", 8 * _1_GiB),
    ("Intel Arc A380", 6 * _1_GiB),
    ("Intel Arc A310", 4 * _1_GiB),
    ("Some Unknown GPU XYZ", 8 * _1_GiB),
    ("NVIDIA GeForce RTX 4090", 8 * _1_GiB),
    ("", 8 * _1_GiB),
)


class TestEstimateMemoryFromName:
    """Gate _estimate_memory_from_name against Intel published VRAM specs.

    Independent oracle: Intel Arc product page VRAM listings (2023-2024):
    B580 = 12 GB GDDR6, A770 = 16 GB GDDR6, A750 = 8 GB GDDR6,
    A380 = 6 GB GDDR6, A310 = 4 GB GDDR6, Unknown = 8 GB default.
    """

    @pytest.mark.parametrize(
        ("device_name", "expected_bytes"),
        _VRAM_TABLE,
    )
    def test_vram_constant_for_device_name(
        self,
        device_name: str,
        expected_bytes: int,
    ) -> None:
        """Exact VRAM byte constant must match Intel published spec for each name.

        Mutation oracle: swapping the B580 (12 GB) and A770 (16 GB) constants
        would cause the B580 row to return 17179869184 instead of 12884901888.

        Args:
            device_name: Device name string as emitted by WMI Win32_VideoController.
            expected_bytes: Expected VRAM in bytes from Intel Arc product page.
        """
        result = _estimate_memory_from_name(device_name)
        assert result == expected_bytes, (
            f"_estimate_memory_from_name({device_name!r}) returned {result} bytes "
            f"(expected {expected_bytes} = {expected_bytes // _1_GiB} GB)"
        )

    @staticmethod
    def test_b580_distinguished_from_a770() -> None:
        """B580 (12 GB) and A770 (16 GB) must return distinct values.

        A mutation returning 16 GB for both would fail on the B580 assertion.
        """
        assert _estimate_memory_from_name("Intel Arc B580") == 12 * _1_GiB
        assert _estimate_memory_from_name("Intel Arc A770") == 16 * _1_GiB

    @staticmethod
    def test_a770_distinguished_from_a750() -> None:
        """A770 (16 GB) and A750 (8 GB) must return distinct values.

        A mutation returning 16 GB for A750 would fail on the second assertion.
        """
        assert _estimate_memory_from_name("Intel Arc A770") == 16 * _1_GiB
        assert _estimate_memory_from_name("Intel Arc A750") == 8 * _1_GiB

    @staticmethod
    def test_a380_distinguished_from_a310() -> None:
        """A380 (6 GB) and A310 (4 GB) must return distinct values.

        A mutation returning 6 GB for A310 would fail on the second assertion.
        """
        assert _estimate_memory_from_name("Intel Arc A380") == 6 * _1_GiB
        assert _estimate_memory_from_name("Intel Arc A310") == 4 * _1_GiB

    @staticmethod
    def test_return_type_is_plain_int() -> None:
        """Return value must be a plain int so byte arithmetic remains exact."""
        result = _estimate_memory_from_name("Intel Arc B580")
        assert type(result) is int

    @staticmethod
    def test_case_insensitive_matching() -> None:
        """Device name matching must be case-insensitive for all SKU branches."""
        assert _estimate_memory_from_name("INTEL ARC B580") == 12 * _1_GiB
        assert _estimate_memory_from_name("intel arc a770") == 16 * _1_GiB
        assert _estimate_memory_from_name("Intel Arc A750 Graphics") == 8 * _1_GiB
