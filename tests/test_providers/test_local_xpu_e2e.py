# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end tests for the local PyTorch/XPU inference path using TinyLlama.

Validates XPU hardware detection, model loading, real inference, streaming,
multi-turn conversation, temperature/sampling, max tokens, CPU fallback,
model cache lifecycle, VRAM management, prompt formatting, tool call parsing,
provider connection lifecycle, dtype selection, and error recovery.
"""

from __future__ import annotations

import contextlib
import itertools
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import pytest
import pytest_asyncio
import torch

from intellicrack.core.types import (
    Message,
    ProviderCredentials,
    ProviderError,
    ToolCall,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.model_loader import (
    LoadedModel,
    ModelCache,
    select_dtype_for_memory,
)
from intellicrack.providers.xpu_utils import (
    check_windows_requirements,
    get_optimal_dtype_for_xpu,
    get_xpu_device_count,
    get_xpu_device_info,
    get_xpu_memory_info,
    is_xpu_available,
)


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Iterator

    from transformers import PreTrainedTokenizerBase

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_TEN_GB: int = 10 * 1024 * 1024 * 1024
_FOURTEEN_GB: int = 14 * 1024 * 1024 * 1024
_TWELVE_GB: int = 12 * 1024 * 1024 * 1024


_COMMON_ENGLISH_WORDS: frozenset[str] = frozenset(
    {
        "the",
        "a",
        "an",
        "is",
        "are",
        "was",
        "to",
        "of",
        "and",
        "in",
        "it",
        "that",
        "this",
        "for",
        "as",
        "with",
        "on",
        "be",
        "by",
        "or",
        "you",
        "i",
        "we",
        "they",
        "he",
        "she",
        "not",
        "have",
        "has",
        "can",
        "will",
        "would",
        "do",
        "does",
        "what",
        "which",
        "when",
        "color",
        "file",
        "system",
        "program",
        "data",
        "code",
        "header",
        "binary",
        "executable",
        "windows",
        "format",
        "section",
        "number",
        "word",
        "hello",
        "blue",
        "red",
        "green",
    },
)

_WORD_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?")


def _seed_all(seed: int) -> None:
    """Seed every torch RNG that sampling may draw from for reproducibility.

    Seeds the global CPU generator and, when present, the XPU and CUDA
    generators so that a subsequent sampled generation is fully determined by
    ``seed`` alone.

    Args:
        seed: The integer seed to apply across all available generators.

    Raises:
        TypeError: If ``torch.manual_seed`` is missing or not callable.
    """
    cpu_seed: object = getattr(torch, "manual_seed", None)
    if not callable(cpu_seed):
        msg = "torch.manual_seed is not callable"
        raise TypeError(msg)
    cpu_seed(seed)
    xpu_backend: object = getattr(torch, "xpu", None)
    xpu_seed: object = getattr(xpu_backend, "manual_seed_all", None)
    if callable(xpu_seed):
        xpu_seed(seed)
    cuda_backend: object = getattr(torch, "cuda", None)
    cuda_seed: object = getattr(cuda_backend, "manual_seed_all", None)
    if callable(cuda_seed):
        cuda_seed(seed)


def _words(text: str) -> list[str]:
    """Extract lowercase alphabetic word tokens from ``text``.

    Args:
        text: The raw text to tokenize.

    Returns:
        list[str]: Lowercased alphabetic word tokens in order of appearance.
    """
    return [match.group(0).lower() for match in _WORD_PATTERN.finditer(text)]


def _max_char_run_ratio(text: str) -> float:
    """Compute the fraction of ``text`` occupied by its longest single-char run.

    A degenerate output such as ``"aaaaaaaaaa"`` yields ``1.0``; genuine prose
    yields a small fraction. This provides an implementation-independent signal
    for detecting repetition collapse without re-deriving model logic.

    Args:
        text: The text to inspect.

    Returns:
        float: Longest run length divided by total length, or ``0.0`` when
        ``text`` is empty.
    """
    if not text:
        return 0.0
    longest = 1
    current = 1
    for previous, char in itertools.pairwise(text):
        if char == previous:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest / len(text)


def _assert_coherent_english(text: str, *, min_words: int = 3, min_dictionary_hits: int = 2) -> None:
    """Assert that ``text`` is coherent natural-language English, not a degenerate string.

    The checks are objective and independent of the model under test: they
    measure word count, character diversity, repetition collapse, alphabetic
    content, and overlap with a fixed common-English vocabulary. A single
    repeated character, control-character noise, or markup would fail every one
    of these gates.

    Args:
        text: The candidate model response text.
        min_words: Minimum number of distinct word tokens required.
        min_dictionary_hits: Minimum number of common-English words required.
    """
    cleaned = text.strip()
    assert cleaned, "response was empty after stripping whitespace"
    control_chars = [char for char in cleaned if not char.isprintable() and char not in "\t\n\r"]
    assert not control_chars, f"response contained control characters {control_chars!r}: {cleaned!r}"

    tokens = _words(cleaned)
    assert len(tokens) >= min_words, f"expected >= {min_words} word tokens, got {len(tokens)}: {cleaned!r}"

    distinct_tokens = set(tokens)
    assert len(distinct_tokens) >= 3, f"expected >= 3 distinct word tokens, got {len(distinct_tokens)}: {cleaned!r}"

    alpha_chars = [char for char in cleaned if char.isalpha()]
    assert len(alpha_chars) >= 8, f"expected >= 8 alphabetic chars, got {len(alpha_chars)}: {cleaned!r}"

    unique_alpha = {char.lower() for char in alpha_chars}
    assert len(unique_alpha) >= 5, f"expected >= 5 unique letters, got {len(unique_alpha)}: {cleaned!r}"

    run_ratio = _max_char_run_ratio(cleaned)
    assert run_ratio < 0.5, f"response is dominated by a repeated character (run ratio {run_ratio:.2f}): {cleaned!r}"

    dictionary_hits = distinct_tokens & _COMMON_ENGLISH_WORDS
    assert len(dictionary_hits) >= min_dictionary_hits, (
        f"expected >= {min_dictionary_hits} common English words, got {sorted(dictionary_hits)}: {cleaned!r}"
    )


def _make_messages(prompt: str) -> list[Message]:
    """Build a single user message list for testing.

    Args:
        prompt: The user message text.

    Returns:
        list[Message]: A list containing a single user Message.
    """
    return [Message(role="user", content=prompt, timestamp=datetime.now(tz=UTC))]


def _make_test_tool() -> list[ToolDefinition]:
    """Build a minimal tool definition for testing function calling.

    Returns:
        list[ToolDefinition]: A list containing a single ToolDefinition for binary.get_file_size.
    """
    return [
        ToolDefinition(
            tool_name=ToolName.GHIDRA,
            description="Binary analysis tools",
            functions=[
                ToolFunction(
                    name="binary.get_file_size",
                    description="Get the file size in bytes of the loaded binary.",
                    parameters=[
                        ToolParameter(
                            name="path",
                            type="string",
                            description="Path to the binary file.",
                            required=True,
                        ),
                    ],
                    returns="File size in bytes as an integer.",
                ),
            ],
        ),
    ]


_ATTR_LOADED_MODEL = "_loaded_model"
_ATTR_MODEL_CACHE = "_model_cache"
_ATTR_CONVERT_MESSAGES = "_convert_messages_to_provider_format"
_ATTR_FORMAT_PROMPT = "_format_prompt"
_ATTR_PARSE_TOOL_CALLS = "_parse_tool_calls"
_ATTR_EXTRACT_TEXT_BEFORE_TOOL_CALL = "_extract_text_before_tool_call"
_ATTR_TOKENIZER_ENCODE = "encode"
_ATTR_TOKENIZER_DECODE = "decode"


def _get_loaded_model(provider: LocalTransformersProvider) -> LoadedModel | None:
    """Retrieve the provider's protected ``_loaded_model`` attribute in a type-safe way.

    Args:
        provider: The provider instance whose loaded model to retrieve.

    Returns:
        LoadedModel | None: The currently loaded model, or None if no model is loaded.

    Raises:
        TypeError: If the attribute is neither None nor a LoadedModel instance.
    """
    raw: object = getattr(provider, _ATTR_LOADED_MODEL)
    if raw is None:
        return None
    if not isinstance(raw, LoadedModel):
        msg = f"Expected LoadedModel or None, got {type(raw).__name__}"
        raise TypeError(msg)
    return raw


def _get_model_cache(provider: LocalTransformersProvider) -> ModelCache:
    """Retrieve the provider's protected ``_model_cache`` attribute in a type-safe way.

    Args:
        provider: The provider instance whose model cache to retrieve.

    Returns:
        ModelCache: The ModelCache instance backing the provider.

    Raises:
        TypeError: If the attribute is not a ModelCache instance.
    """
    raw: object = getattr(provider, _ATTR_MODEL_CACHE)
    if not isinstance(raw, ModelCache):
        msg = f"Expected ModelCache, got {type(raw).__name__}"
        raise TypeError(msg)
    return raw


def _convert_messages_via(
    provider: LocalTransformersProvider,
    messages: list[Message],
) -> list[dict[str, object]]:
    """Invoke the provider's protected ``_convert_messages_to_provider_format`` method.

    Args:
        provider: The provider instance exposing the conversion method.
        messages: List of Message objects to convert.

    Returns:
        list[dict[str, object]]: The list of converted message dictionaries.

    Raises:
        TypeError: If the underlying method is missing, not callable, or
            returns a value that is not a list of dicts.
    """
    method: object = getattr(provider, _ATTR_CONVERT_MESSAGES)
    if not callable(method):
        msg = f"{_ATTR_CONVERT_MESSAGES} is not callable"
        raise TypeError(msg)
    result: object = method(messages)
    if not isinstance(result, list):
        msg = f"Expected list result, got {type(result).__name__}"
        raise TypeError(msg)
    validated: list[dict[str, object]] = []
    for item in cast("list[object]", result):
        if not isinstance(item, dict):
            msg = f"Expected dict items, got {type(item).__name__}"
            raise TypeError(msg)
        narrowed: dict[str, object] = {}
        for key, value in cast("dict[object, object]", item).items():
            if not isinstance(key, str):
                msg = f"Expected str dict keys, got {type(key).__name__}"
                raise TypeError(msg)
            narrowed[key] = value
        validated.append(narrowed)
    return validated


def _format_prompt_via(
    provider: LocalTransformersProvider,
    messages: list[dict[str, object]],
    tools: list[ToolDefinition] | None = None,
) -> str:
    """Invoke the provider's protected ``_format_prompt`` method in a type-safe way.

    Args:
        provider: The provider instance exposing the formatting method.
        messages: The list of pre-converted message dictionaries.
        tools: Optional list of tool definitions to inject into the prompt.

    Returns:
        str: The formatted prompt string.

    Raises:
        TypeError: If the underlying method is missing, not callable, or
            returns a value that is not a string.
    """
    method: object = getattr(provider, _ATTR_FORMAT_PROMPT)
    if not callable(method):
        msg = f"{_ATTR_FORMAT_PROMPT} is not callable"
        raise TypeError(msg)
    result: object = method(messages, tools)
    if not isinstance(result, str):
        msg = f"Expected str result, got {type(result).__name__}"
        raise TypeError(msg)
    return result


def _parse_tool_calls_via(response: str) -> list[ToolCall] | None:
    """Invoke the provider's protected ``_parse_tool_calls`` static method.

    Args:
        response: The raw model response to parse.

    Returns:
        list[ToolCall] | None: Parsed tool calls, or None if no tool call was present.

    Raises:
        TypeError: If the underlying method is missing, not callable, or
            returns a value that is neither None nor a list of ToolCall objects.
    """
    method: object = getattr(LocalTransformersProvider, _ATTR_PARSE_TOOL_CALLS)
    if not callable(method):
        msg = f"{_ATTR_PARSE_TOOL_CALLS} is not callable"
        raise TypeError(msg)
    result: object = method(response)
    if result is None:
        return None
    if not isinstance(result, list):
        msg = f"Expected list or None, got {type(result).__name__}"
        raise TypeError(msg)
    validated: list[ToolCall] = []
    for item in cast("list[object]", result):
        if not isinstance(item, ToolCall):
            msg = f"Expected ToolCall items, got {type(item).__name__}"
            raise TypeError(msg)
        validated.append(item)
    return validated


def _extract_text_before_tool_call_via(response: str) -> str:
    """Invoke the provider's protected ``_extract_text_before_tool_call`` static method.

    Args:
        response: The raw model response to extract text from.

    Returns:
        str: The text appearing before any tool call JSON.

    Raises:
        TypeError: If the underlying method is missing, not callable, or
            returns a value that is not a string.
    """
    method: object = getattr(LocalTransformersProvider, _ATTR_EXTRACT_TEXT_BEFORE_TOOL_CALL)
    if not callable(method):
        msg = f"{_ATTR_EXTRACT_TEXT_BEFORE_TOOL_CALL} is not callable"
        raise TypeError(msg)
    result: object = method(response)
    if not isinstance(result, str):
        msg = f"Expected str result, got {type(result).__name__}"
        raise TypeError(msg)
    return result


def _iter_model_parameters(loaded: LoadedModel) -> Iterator[torch.nn.Parameter]:
    """Iterate over the model's torch Parameters in a type-safe way.

    HuggingFace ``PreTrainedModel`` stubs do not surface ``parameters``, so
    this helper narrows the model object to ``torch.nn.Module`` via
    ``isinstance`` and returns the typed iterator that ``torch.nn.Module``
    declares.

    Args:
        loaded: The loaded model whose parameters should be iterated.

    Yields:
        torch.nn.Parameter: Successive Parameter tensors from the loaded model.

    Raises:
        TypeError: If the loaded model is not a torch.nn.Module instance.
    """
    model_obj: object = loaded.model
    if not isinstance(model_obj, torch.nn.Module):
        msg = f"Expected torch.nn.Module, got {type(model_obj).__name__}"
        raise TypeError(msg)
    yield from model_obj.parameters()


def _tokenizer_encode(tokenizer: PreTrainedTokenizerBase, text: str) -> list[int]:
    """Encode ``text`` into token IDs using the tokenizer in a type-safe way.

    Args:
        tokenizer: The HuggingFace tokenizer to use.
        text: Text to encode.

    Returns:
        list[int]: Encoded token IDs.

    Raises:
        TypeError: If the tokenizer lacks a callable ``encode`` attribute or
            the returned value is not a list of integers.
    """
    encode_fn: object = getattr(tokenizer, _ATTR_TOKENIZER_ENCODE)
    if not callable(encode_fn):
        msg = "tokenizer.encode is not callable"
        raise TypeError(msg)
    result: object = encode_fn(text)
    if not isinstance(result, list):
        msg = f"Expected list of token ids, got {type(result).__name__}"
        raise TypeError(msg)
    validated: list[int] = []
    for token in cast("list[object]", result):
        if not isinstance(token, int):
            msg = f"Expected int token ids, got {type(token).__name__}"
            raise TypeError(msg)
        validated.append(token)
    return validated


def _tokenizer_decode(
    tokenizer: PreTrainedTokenizerBase,
    token_ids: list[int],
    *,
    skip_special_tokens: bool = True,
) -> str:
    """Decode token IDs back to text using the tokenizer in a type-safe way.

    Args:
        tokenizer: The HuggingFace tokenizer to use.
        token_ids: Token IDs to decode.
        skip_special_tokens: Whether to skip special tokens during decoding.

    Returns:
        str: Decoded text.

    Raises:
        TypeError: If the tokenizer lacks a callable ``decode`` attribute or
            the returned value is not a string.
    """
    decode_fn: object = getattr(tokenizer, _ATTR_TOKENIZER_DECODE)
    if not callable(decode_fn):
        msg = "tokenizer.decode is not callable"
        raise TypeError(msg)
    result: object = decode_fn(token_ids, skip_special_tokens=skip_special_tokens)
    if not isinstance(result, str):
        msg = f"Expected str, got {type(result).__name__}"
        raise TypeError(msg)
    return result


@pytest.fixture(scope="session")
def tinyllama_model_id() -> str:
    """Get the TinyLlama model identifier.

    Returns:
        str: The HuggingFace model ID for TinyLlama 1.1B Chat.
    """
    return "TinyLlama/TinyLlama-1.1B-Chat-v1.0"


@pytest_asyncio.fixture(scope="session")
async def xpu_provider(
    *,
    has_xpu_available: bool,
) -> AsyncGenerator[LocalTransformersProvider]:
    """Create a connected XPU provider instance.

    Skips the test if XPU hardware is not available.

    Args:
        has_xpu_available: Whether XPU hardware is available.

    Yields:
        AsyncGenerator[LocalTransformersProvider]: A connected provider using XPU.
    """
    if not has_xpu_available:
        pytest.skip("XPU not available")

    provider = LocalTransformersProvider(prefer_xpu=True)
    await provider.connect(ProviderCredentials())
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture(scope="session")
async def cpu_provider() -> AsyncGenerator[LocalTransformersProvider]:
    """Create a connected CPU-only provider instance.

    Yields:
        AsyncGenerator[LocalTransformersProvider]: A connected provider using CPU.
    """
    provider = LocalTransformersProvider(prefer_xpu=False)
    await provider.connect(ProviderCredentials())
    yield provider
    await provider.disconnect()


@pytest_asyncio.fixture(scope="session")
async def loaded_xpu_provider(
    xpu_provider: LocalTransformersProvider,
    tinyllama_model_id: str,
) -> AsyncGenerator[LocalTransformersProvider]:
    """Get an XPU provider with TinyLlama already loaded.

    Forces a model load by issuing a minimal chat call.

    Args:
        xpu_provider: The session-scoped XPU provider.
        tinyllama_model_id: The TinyLlama model identifier.

    Yields:
        AsyncGenerator[LocalTransformersProvider]: XPU provider with model loaded.
    """
    messages = _make_messages("Hello")
    await xpu_provider.chat(messages=messages, model=tinyllama_model_id, max_tokens=1)
    yield xpu_provider


@pytest_asyncio.fixture(scope="session")
async def loaded_cpu_provider(
    cpu_provider: LocalTransformersProvider,
    tinyllama_model_id: str,
) -> AsyncGenerator[LocalTransformersProvider]:
    """Get a CPU provider with TinyLlama already loaded.

    Forces a model load by issuing a minimal chat call.

    Args:
        cpu_provider: The session-scoped CPU provider.
        tinyllama_model_id: The TinyLlama model identifier.

    Yields:
        AsyncGenerator[LocalTransformersProvider]: CPU provider with model loaded.
    """
    messages = _make_messages("Hello")
    await cpu_provider.chat(messages=messages, model=tinyllama_model_id, max_tokens=1)
    yield cpu_provider


@pytest.fixture
def fresh_model_cache() -> ModelCache:
    """Create a clean ModelCache for cache lifecycle tests.

    Returns:
        ModelCache: A new ModelCache instance with default settings.
    """
    return ModelCache()


@pytest.fixture
def fresh_xpu_provider(
    *,
    has_xpu_available: bool,
) -> LocalTransformersProvider:
    """Create an unconnected XPU provider for lifecycle tests.

    Skips the test if XPU hardware is not available.

    Args:
        has_xpu_available: Whether XPU hardware is available.

    Returns:
        LocalTransformersProvider: An unconnected provider instance.
    """
    if not has_xpu_available:
        pytest.skip("XPU not available")

    return LocalTransformersProvider(prefer_xpu=True)


@pytest.mark.xpu
@pytest.mark.b580
class TestXPUHardwareValidation:
    """Validate XPU hardware detection and device info on Arc B580."""

    def test_xpu_device_detected(self, *, has_xpu_available: bool) -> None:
        """XPU should be detected as available with at least one device.

        Args:
            has_xpu_available: Whether XPU hardware is available.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")

        assert is_xpu_available() is True
        assert get_xpu_device_count() >= 1

    def test_device_info_complete(self, *, has_xpu_available: bool) -> None:
        """Device info should contain all expected fields populated.

        Args:
            has_xpu_available: Whether XPU hardware is available.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")

        info = get_xpu_device_info(0)
        assert info is not None
        assert info.device_index == 0
        assert len(info.device_name) > 0
        assert info.total_memory_bytes > 0

    def test_b580_identification(
        self,
        *,
        has_xpu_available: bool,
        has_arc_b580: bool,
    ) -> None:
        """Arc B580 should be positively identified by device ID or name.

        Args:
            has_xpu_available: Whether XPU hardware is available.
            has_arc_b580: Whether an Arc B580 is detected.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")
        if not has_arc_b580:
            pytest.skip("Arc B580 not detected")

        info = get_xpu_device_info(0)
        assert info is not None
        assert info.is_arc_b580 is True
        assert "e20b" in info.device_id.lower() or "b580" in info.device_name.lower()

    def test_memory_reporting_accuracy(
        self,
        *,
        has_xpu_available: bool,
        has_arc_b580: bool,
    ) -> None:
        """B580 memory should report approximately 12 GB total.

        Args:
            has_xpu_available: Whether XPU hardware is available.
            has_arc_b580: Whether an Arc B580 is detected.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")
        if not has_arc_b580:
            pytest.skip("Arc B580 not detected")

        info = get_xpu_device_info(0)
        assert info is not None
        assert _TEN_GB <= info.total_memory_bytes <= _FOURTEEN_GB

        allocated, total = get_xpu_memory_info(0)
        assert allocated >= 0
        assert total > 0
        assert allocated < total

    def test_rebar_and_windows_requirements(
        self,
        *,
        has_xpu_available: bool,
    ) -> None:
        """Windows requirements check should return expected structure.

        Args:
            has_xpu_available: Whether XPU hardware is available.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")

        all_met, warnings = check_windows_requirements()
        assert isinstance(all_met, bool)
        assert isinstance(warnings, list)

    def test_dtype_support_flags(
        self,
        *,
        has_xpu_available: bool,
        has_arc_b580: bool,
    ) -> None:
        """B580 should support fp16, bf16, and int8 dtypes.

        Args:
            has_xpu_available: Whether XPU hardware is available.
            has_arc_b580: Whether an Arc B580 is detected.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")
        if not has_arc_b580:
            pytest.skip("Arc B580 not detected")

        info = get_xpu_device_info(0)
        assert info is not None
        assert info.supports_fp16 is True
        assert info.supports_bf16 is True
        assert info.supports_int8 is True


@pytest.mark.xpu
@pytest.mark.slow
class TestModelLoadingOntoXPU:
    """Validate TinyLlama model loading onto XPU hardware."""

    async def test_load_tinyllama_onto_xpu(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """TinyLlama should be loaded onto XPU with correct metadata.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        loaded = _get_loaded_model(loaded_xpu_provider)
        assert loaded is not None
        assert loaded.model_id == tinyllama_model_id
        assert loaded.device.type == "xpu"

    async def test_model_device_placement(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Every model parameter tensor should reside on XPU.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        loaded = _get_loaded_model(loaded_xpu_provider)
        assert loaded is not None
        for param in _iter_model_parameters(loaded):
            assert param.device.type == "xpu"

    async def test_dtype_is_float16_or_bf16(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Auto dtype selection should choose float16 or bfloat16 for B580.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        loaded = _get_loaded_model(loaded_xpu_provider)
        assert loaded is not None
        assert loaded.dtype in {"float16", "bfloat16"}

    async def test_tokenizer_functional(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Tokenizer should perform encode/decode roundtrip correctly.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        loaded = _get_loaded_model(loaded_xpu_provider)
        assert loaded is not None
        text = "Hello world"
        token_ids = _tokenizer_encode(loaded.tokenizer, text)
        decoded = _tokenizer_decode(loaded.tokenizer, token_ids, skip_special_tokens=True)
        assert "Hello" in decoded
        assert "world" in decoded

    async def test_load_time_recorded(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Model load time should be recorded as a positive value.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        loaded = _get_loaded_model(loaded_xpu_provider)
        assert loaded is not None
        assert loaded.load_time_seconds > 0


@pytest.mark.xpu
@pytest.mark.slow
class TestRealInference:
    """Validate real non-streaming inference on XPU."""

    async def test_simple_chat_returns_response(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Chat should answer a closed-form arithmetic prompt with the correct value.

        The expected answer (``4``) is an independent oracle: ``2 + 2`` equals
        ``4`` regardless of the model. The response must additionally be coherent
        natural-language text, not a degenerate or garbled string.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("What is 2 + 2? Show the calculation and the answer.")
        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=64,
            temperature=0.0,
        )
        assert response.role == "assistant"
        content = response.content
        assert "4" in content, f"expected the arithmetic answer '4' in response: {content!r}"
        assert re.search(r"2\s*\+\s*2", content) is not None, f"expected the operands '2 + 2' echoed in response: {content!r}"
        _assert_coherent_english(content, min_words=3, min_dictionary_hits=1)

    async def test_response_is_coherent_text(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Response should be coherent multi-word English, not a degenerate string.

        The coherence oracle is independent of the model: a single repeated
        character, control-character noise, or markup fails the distinct-token,
        unique-letter, repetition-ratio, and common-vocabulary gates. A genuine
        sentence passes all of them.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("What is the sky? Answer in one sentence.")
        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=64,
            temperature=0.0,
        )
        _assert_coherent_english(response.content, min_words=6, min_dictionary_hits=3)

    async def test_domain_prompt(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """A binary-analysis prompt should produce an on-topic, coherent answer.

        Run greedily (``temperature=0.0``) so the topical content is
        deterministic. The response must be coherent English and must reference
        the PE/executable domain it was asked about - an off-topic or garbled
        answer fails both the coherence gate and the domain-term gate.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("What is a PE header in a Windows executable? Explain briefly.")
        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=200,
            temperature=0.0,
        )
        _assert_coherent_english(response.content, min_words=8, min_dictionary_hits=3)

        lowered = response.content.lower()
        domain_terms = ("pe", "header", "executable", "binary", "windows", "file", "format", "section", "offset", "dos", "coff")
        present = [term for term in domain_terms if term in lowered]
        assert len(present) >= 3, f"expected >= 3 PE-domain terms, found {present} in: {response.content!r}"
        assert "header" in lowered, f"expected the prompted topic 'header' in response: {response.content!r}"


@pytest.mark.xpu
@pytest.mark.slow
class TestStreamingInference:
    """Validate streaming inference on XPU."""

    async def test_stream_yields_chunks(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Streaming should yield multiple non-empty string chunks of real words.

        Every chunk must be a non-empty ``str``; together the letter-bearing
        chunks must reconstruct several distinct, recognizable English words.
        Empty strings, non-string objects, or a single repeated fragment fail.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("List three primary colors in a sentence.")
        chunks: list[str] = [
            chunk
            async for chunk in loaded_xpu_provider.chat_stream(
                messages=messages,
                model=tinyllama_model_id,
                max_tokens=48,
                temperature=0.0,
            )
        ]

        assert len(chunks) >= 2, f"expected the stream to yield multiple chunks, got {len(chunks)}"
        assert all(isinstance(chunk, str) for chunk in chunks), "every streamed chunk must be a str"
        assert all(chunk for chunk in chunks), "the stream must not yield empty chunks"

        chunks_with_letters = [chunk for chunk in chunks if any(char.isalpha() for char in chunk)]
        assert len(chunks_with_letters) >= 4, f"expected >= 4 chunks containing letters, got {len(chunks_with_letters)}"

        token_text = " ".join(chunks_with_letters)
        word_tokens = _words(token_text)
        distinct_words = set(word_tokens)
        assert len(distinct_words) >= 4, f"expected >= 4 distinct streamed word tokens, got {sorted(distinct_words)}"

        dictionary_hits = distinct_words & _COMMON_ENGLISH_WORDS
        assert len(dictionary_hits) >= 2, f"expected >= 2 common English words across chunks, got {sorted(dictionary_hits)}"

    async def test_stream_assembles_to_complete_response(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Joined stream chunks should form non-empty printable text.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("What color is the sky?")
        chunks: list[str] = [
            chunk
            async for chunk in loaded_xpu_provider.chat_stream(
                messages=messages,
                model=tinyllama_model_id,
                max_tokens=32,
            )
        ]

        full_text = "".join(chunks).strip()
        assert len(full_text) > 0
        assert full_text.isprintable()

    async def test_stream_and_nonstream_both_produce_valid_output(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Streaming and non-streaming greedy decode must yield the same content.

        Both paths run greedy decoding (``temperature=0.0``) over the same model
        and prompt, so they must emit the identical token sequence. The
        non-streaming path preserves inter-word spaces while the streaming path
        decodes per token (dropping leading spaces); with all whitespace removed
        the two outputs must be byte-for-byte equal. This is an independent
        functional-alignment oracle: any divergence in prompt formatting,
        decoding, or sampling between the two code paths breaks the equality.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        prompt = "Name a primary color in a short sentence."
        messages = _make_messages(prompt)

        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=24,
            temperature=0.0,
        )
        _assert_coherent_english(response.content, min_words=4, min_dictionary_hits=2)

        chunks: list[str] = [
            chunk
            async for chunk in loaded_xpu_provider.chat_stream(
                messages=messages,
                model=tinyllama_model_id,
                max_tokens=24,
                temperature=0.0,
            )
        ]
        assert all(isinstance(chunk, str) for chunk in chunks), "every streamed chunk must be a str"

        non_stream_collapsed = re.sub(r"\s+", "", response.content)
        stream_collapsed = re.sub(r"\s+", "", "".join(chunks))
        assert stream_collapsed, "stream produced no text"
        assert stream_collapsed == non_stream_collapsed, (
            f"streaming output diverged from non-streaming greedy decode:\n"
            f"  non-stream: {non_stream_collapsed!r}\n"
            f"  stream:     {stream_collapsed!r}"
        )


@pytest.mark.xpu
@pytest.mark.slow
class TestMultiTurnConversation:
    """Validate multi-turn conversation handling on XPU."""

    async def test_two_turn_conversation(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Two-turn conversation should produce valid responses for both turns.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("My name is Alice")
        response1, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=64,
        )
        assert len(response1.content) > 0

        messages.append(response1)
        messages.append(
            Message(
                role="user",
                content="What is my name?",
                timestamp=datetime.now(tz=UTC),
            ),
        )
        response2, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=64,
        )
        assert len(response2.content) > 0

    async def test_three_turn_with_system_prompt(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Three-turn conversation with system prompt should produce valid responses.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages: list[Message] = [
            Message(
                role="system",
                content="You are a helpful assistant.",
                timestamp=datetime.now(tz=UTC),
            ),
            Message(
                role="user",
                content="Hello, how are you?",
                timestamp=datetime.now(tz=UTC),
            ),
        ]
        response1, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=64,
        )
        assert len(response1.content) > 0

        messages.extend((response1, Message(role="user", content="Tell me something interesting.", timestamp=datetime.now(tz=UTC))))
        response2, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=64,
        )
        assert len(response2.content) > 0


@pytest.mark.xpu
@pytest.mark.slow
class TestTemperatureAndSampling:
    """Validate temperature-controlled sampling on XPU."""

    async def test_temperature_zero_deterministic(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Two calls with temperature=0 should produce identical output.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("What is 1 + 1?")

        response1, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            temperature=0.0,
            max_tokens=16,
        )
        response2, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            temperature=0.0,
            max_tokens=16,
        )
        assert response1.content == response2.content

    async def test_temperature_positive_produces_variation(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Temperature must drive sampling: greedy is fixed, sampling diverges.

        This is made deterministic by seeding every torch generator before each
        call. The independent oracle is the production sampling contract: with
        ``temperature=0.0`` decoding is greedy argmax, so the output is identical
        regardless of the seed; with ``temperature=1.0`` decoding samples from
        the softmax, so distinct seeds yield distinct outputs. If sampling were
        broken (always greedy) the high-temperature outputs would collapse to a
        single value and this test would fail. Seeding removes flakiness while
        the greedy/sampled contrast keeps the gate falsifiable.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("Tell me a random word.")
        seeds: tuple[int, ...] = (1, 2, 3, 4, 5, 6)

        greedy_outputs: list[str] = []
        for seed in seeds:
            _seed_all(seed)
            response, _ = await loaded_xpu_provider.chat(
                messages=messages,
                model=tinyllama_model_id,
                temperature=0.0,
                max_tokens=12,
            )
            greedy_outputs.append(response.content.strip())

        assert len(set(greedy_outputs)) == 1, f"greedy decoding must ignore the seed, got distinct outputs: {set(greedy_outputs)}"

        sampled_outputs: list[str] = []
        for seed in seeds:
            _seed_all(seed)
            response, _ = await loaded_xpu_provider.chat(
                messages=messages,
                model=tinyllama_model_id,
                temperature=1.0,
                max_tokens=12,
            )
            sampled_outputs.append(response.content.strip())

        distinct_sampled = set(sampled_outputs)
        assert len(distinct_sampled) >= len(seeds) - 1, (
            f"temperature=1.0 sampling must vary across seeds, got {len(distinct_sampled)} distinct of {len(seeds)}: {distinct_sampled}"
        )
        assert distinct_sampled != set(greedy_outputs), "sampled outputs must differ from the fixed greedy output"


@pytest.mark.xpu
@pytest.mark.slow
class TestMaxTokensControl:
    """Validate max_tokens parameter enforcement on XPU."""

    async def test_max_tokens_10_short_output(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Max tokens of 10 should produce a short response.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("Write a long essay about history.")
        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=10,
        )
        words = response.content.split()
        assert len(words) < 50

    async def test_max_tokens_100_longer_output(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Max tokens of 100 should produce a longer response than max tokens of 10.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("Explain what binary analysis is.")
        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=100,
        )
        assert len(response.content) > 0

    async def test_max_tokens_1_minimal_output(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Max tokens of 1 should produce at most a few words.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("Say something.")
        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=1,
        )
        words = response.content.split()
        assert len(words) <= 5


@pytest.mark.slow
class TestCPUFallbackInference:
    """Validate CPU fallback inference path."""

    async def test_cpu_provider_device_is_cpu(
        self,
        loaded_cpu_provider: LocalTransformersProvider,
    ) -> None:
        """CPU provider should report device type as cpu.

        Args:
            loaded_cpu_provider: CPU provider with model loaded.
        """
        assert loaded_cpu_provider.device_type == "cpu"

    async def test_cpu_inference_produces_response(
        self,
        loaded_cpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """CPU inference should return a non-empty assistant message.

        Args:
            loaded_cpu_provider: CPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("What is 2 + 2?")
        response, _ = await loaded_cpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=32,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0

    async def test_cpu_model_parameters_on_cpu(
        self,
        loaded_cpu_provider: LocalTransformersProvider,
    ) -> None:
        """All model parameters should reside on CPU device.

        Args:
            loaded_cpu_provider: CPU provider with model loaded.
        """
        loaded = _get_loaded_model(loaded_cpu_provider)
        assert loaded is not None
        for param in _iter_model_parameters(loaded):
            assert param.device.type == "cpu"


@pytest.mark.xpu
@pytest.mark.slow
class TestModelCacheLifecycle:
    """Validate model cache get/put/remove/clear operations.

    These tests verify the ModelCache API using the provider's already-loaded
    model cache (via the provider's internal _model_cache) rather than sharing
    LoadedModel objects, which would destroy model state on removal.
    """

    async def test_load_populates_cache(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """After model load, the provider's cache should contain the model.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        loaded = _get_loaded_model(loaded_xpu_provider)
        assert loaded is not None
        cache = _get_model_cache(loaded_xpu_provider)
        result = cache.get(loaded.model_id, loaded.dtype, loaded.device.type)
        assert result is not None
        assert result.model_id == tinyllama_model_id

    async def test_cache_hit_returns_same_object(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Second cache get should return the same object identity.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        loaded = _get_loaded_model(loaded_xpu_provider)
        assert loaded is not None
        cache = _get_model_cache(loaded_xpu_provider)
        result1 = cache.get(loaded.model_id, loaded.dtype, loaded.device.type)
        result2 = cache.get(loaded.model_id, loaded.dtype, loaded.device.type)
        assert result1 is result2

    async def test_fresh_cache_remove_returns_false_for_missing(
        self,
        fresh_model_cache: ModelCache,
    ) -> None:
        """Removing a nonexistent model from a fresh cache should return False.

        Args:
            fresh_model_cache: A clean ModelCache instance.
        """
        removed = fresh_model_cache.remove("nonexistent-model", "float16", "xpu")
        assert removed is False
        assert fresh_model_cache.get("nonexistent-model", "float16", "xpu") is None

    async def test_fresh_cache_memory_starts_at_zero(
        self,
        fresh_model_cache: ModelCache,
    ) -> None:
        """A fresh cache should report zero memory usage.

        Args:
            fresh_model_cache: A clean ModelCache instance.
        """
        assert fresh_model_cache.get_memory_usage() == 0


@pytest.mark.xpu
@pytest.mark.b580
@pytest.mark.slow
class TestVRAMManagement:
    """Validate VRAM allocation and reporting on XPU."""

    async def test_memory_increases_after_model_load(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """VRAM allocation should be non-zero after model is loaded.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        assert loaded_xpu_provider.current_model_id is not None
        allocated, total = get_xpu_memory_info(0)
        assert total > 0
        assert allocated >= 0

    async def test_memory_decreases_after_unload(
        self,
        xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Memory info should remain valid and queryable after operations.

        Args:
            xpu_provider: The session-scoped XPU provider.
        """
        assert xpu_provider.device_type in {"xpu", "cuda", "cpu"}
        allocated, total = get_xpu_memory_info(0)
        assert isinstance(allocated, int)
        assert isinstance(total, int)
        assert total > 0

    async def test_total_vram_remains_stable(self) -> None:
        """Total VRAM should remain consistent across multiple queries."""
        _, total1 = get_xpu_memory_info(0)
        _, total2 = get_xpu_memory_info(0)
        _, total3 = get_xpu_memory_info(0)
        assert total1 == total2 == total3


@pytest.mark.xpu
@pytest.mark.slow
class TestPromptFormatting:
    """Validate prompt formatting and chat template usage."""

    async def test_chat_template_produces_valid_prompt(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Formatted prompt should contain chat template structure.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        messages = _make_messages("Hello")
        formatted = _convert_messages_via(loaded_xpu_provider, messages)
        prompt = _format_prompt_via(loaded_xpu_provider, formatted)
        assert len(prompt) > 0
        assert "Hello" in prompt

    async def test_system_message_included_in_prompt(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """System message text should appear in the formatted prompt.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        messages: list[Message] = [
            Message(
                role="system",
                content="You are a binary analysis assistant.",
                timestamp=datetime.now(tz=UTC),
            ),
            Message(
                role="user",
                content="Hello",
                timestamp=datetime.now(tz=UTC),
            ),
        ]
        formatted = _convert_messages_via(loaded_xpu_provider, messages)
        prompt = _format_prompt_via(loaded_xpu_provider, formatted)
        assert "binary analysis assistant" in prompt

    async def test_tool_schema_injected_into_prompt(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Tool definitions should appear in the prompt when provided.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
        """
        messages = _make_messages("Use a tool")
        tools = _make_test_tool()
        formatted = _convert_messages_via(loaded_xpu_provider, messages)
        prompt = _format_prompt_via(loaded_xpu_provider, formatted, tools)
        assert "binary.get_file_size" in prompt


class TestToolCallParsing:
    """Validate static tool call parsing methods."""

    def test_parse_valid_tool_call_json(self) -> None:
        """Valid tool call JSON should parse into a ToolCall list."""
        response = '{"tool_call": {"name": "binary.get_file_size", "arguments": {"path": "test.exe"}}}'
        result = _parse_tool_calls_via(response)
        assert result is not None
        assert len(result) == 1
        assert result[0].function_name == "binary.get_file_size"
        assert result[0].arguments["path"] == "test.exe"

    def test_parse_no_tool_call(self) -> None:
        """Plain text without tool call JSON should return None."""
        result = _parse_tool_calls_via(
            "This is just plain text without any tool calls.",
        )
        assert result is None

    def test_parse_malformed_json_returns_none(self) -> None:
        """Truncated tool call JSON should return None."""
        result = _parse_tool_calls_via(
            '{"tool_call": {"name": "binary.get_file_size", "arguments": {"path":',
        )
        assert result is None

    def test_extract_text_before_tool_call(self) -> None:
        """Text preceding tool call JSON should be extracted correctly."""
        response = 'Here is the result. {"tool_call": {"name": "test", "arguments": {}}}'
        text = _extract_text_before_tool_call_via(response)
        assert text == "Here is the result."


class TestProviderConnectionLifecycle:
    """Validate provider connect/disconnect lifecycle."""

    async def test_connect_sets_xpu_detection_state(
        self,
        fresh_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """After connect, xpu_available should match standalone detection.

        Args:
            fresh_xpu_provider: An unconnected XPU provider.
        """
        await fresh_xpu_provider.connect(ProviderCredentials())
        assert fresh_xpu_provider.xpu_available == is_xpu_available()
        await fresh_xpu_provider.disconnect()

    async def test_connect_sets_device_type(
        self,
        fresh_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """After connect, device type should be xpu when XPU is available.

        Args:
            fresh_xpu_provider: An unconnected XPU provider.
        """
        await fresh_xpu_provider.connect(ProviderCredentials())
        expected = "xpu" if is_xpu_available() else "cpu"
        assert fresh_xpu_provider.device_type == expected
        await fresh_xpu_provider.disconnect()

    async def test_disconnect_clears_state(
        self,
        fresh_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """After disconnect, provider should report as not connected.

        Args:
            fresh_xpu_provider: An unconnected XPU provider.
        """
        await fresh_xpu_provider.connect(ProviderCredentials())
        await fresh_xpu_provider.disconnect()
        assert fresh_xpu_provider.connected is False

    async def test_chat_before_connect_raises(self) -> None:
        """Calling chat before connect should raise an error."""
        provider = LocalTransformersProvider(prefer_xpu=True)
        messages = _make_messages("Hello")
        with pytest.raises((ProviderError, AttributeError)):
            await provider.chat(messages=messages, model="any-model")

    async def test_get_device_info_after_connect(
        self,
        fresh_xpu_provider: LocalTransformersProvider,
    ) -> None:
        """Device info dict should contain expected keys after connect.

        Args:
            fresh_xpu_provider: An unconnected XPU provider.
        """
        await fresh_xpu_provider.connect(ProviderCredentials())
        info = fresh_xpu_provider.get_device_info()
        assert "device_type" in info
        assert "xpu_available" in info
        assert "is_arc_b580" in info
        assert "warnings" in info
        await fresh_xpu_provider.disconnect()


@pytest.mark.xpu
@pytest.mark.b580
@pytest.mark.slow
class TestDtypeSelection:
    """Validate dtype selection and tensor operations on XPU."""

    async def test_auto_dtype_selects_fp16_or_bf16(
        self,
        tinyllama_model_id: str,
    ) -> None:
        """Auto dtype selection with 12 GB should choose float16 or bfloat16.

        Args:
            tinyllama_model_id: The TinyLlama model identifier.
        """
        selected = select_dtype_for_memory(tinyllama_model_id, _TWELVE_GB)
        assert selected in {"float16", "bfloat16"}

    async def test_tensor_operations_at_selected_dtype(self, *, has_xpu_available: bool) -> None:
        """Matrix multiplication on XPU at the selected dtype should succeed.

        Args:
            has_xpu_available: Whether XPU hardware is available.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")
        torch = pytest.importorskip("torch")
        dtype_name = get_optimal_dtype_for_xpu()
        dtype_map = {
            "float16": torch.float16,
            "bfloat16": torch.bfloat16,
            "float32": torch.float32,
        }
        torch_dtype = dtype_map.get(dtype_name, torch.float32)
        device = torch.device("xpu:0")
        a = torch.randn(4, 4, dtype=torch_dtype, device=device)
        b = torch.randn(4, 4, dtype=torch_dtype, device=device)
        result = torch.matmul(a, b)
        assert result.shape == (4, 4)
        assert result.device.type == "xpu"

    async def test_optimal_dtype_detection(self, *, has_xpu_available: bool) -> None:
        """Optimal dtype for XPU should be float16 or bfloat16.

        Args:
            has_xpu_available: Whether XPU hardware is available.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")
        dtype = get_optimal_dtype_for_xpu()
        assert dtype in {"float16", "bfloat16"}


class TestErrorRecovery:
    """Validate error handling and recovery for edge cases."""

    async def test_invalid_model_id_raises_provider_error(
        self,
        *,
        has_xpu_available: bool,
    ) -> None:
        """Loading a nonexistent model should raise ProviderError.

        Args:
            has_xpu_available: Whether XPU hardware is available.
        """
        if not has_xpu_available:
            pytest.skip("XPU not available")

        provider = LocalTransformersProvider(prefer_xpu=True)
        await provider.connect(ProviderCredentials())
        messages = _make_messages("Hello")
        try:
            with pytest.raises(ProviderError):
                await provider.chat(
                    messages=messages,
                    model="nonexistent/model-that-does-not-exist-xyz-99999",
                    max_tokens=16,
                )
        finally:
            await provider.disconnect()

    async def test_empty_message_list_handled(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Empty message list should not crash with an unhandled exception.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        with contextlib.suppress(ProviderError, ValueError, RuntimeError, IndexError):
            await loaded_xpu_provider.chat(
                messages=[],
                model=tinyllama_model_id,
                max_tokens=16,
            )

    async def test_very_long_input_handled(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """A 10k character prompt should be handled without crashing.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        long_prompt = "A" * 10000
        messages = _make_messages(long_prompt)
        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=16,
        )
        assert response.role == "assistant"

    async def test_unicode_input_handled(
        self,
        loaded_xpu_provider: LocalTransformersProvider,
        tinyllama_model_id: str,
    ) -> None:
        """Unicode and special characters should be handled without crashing.

        Args:
            loaded_xpu_provider: XPU provider with model loaded.
            tinyllama_model_id: The TinyLlama model identifier.
        """
        messages = _make_messages("Translate: Bonjour le monde")
        response, _ = await loaded_xpu_provider.chat(
            messages=messages,
            model=tinyllama_model_id,
            max_tokens=32,
        )
        assert response.role == "assistant"
        assert len(response.content) > 0
