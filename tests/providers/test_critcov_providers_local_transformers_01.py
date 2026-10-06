# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for ``intellicrack.providers.local_transformers``.

These tests drive the provider's guard, failure, fallback, cancellation and bookkeeping paths against real objects. A single small model
(``TinyLlama/TinyLlama-1.1B-Chat-v1.0``, the one baked into the container's Hugging Face cache) is loaded once per file on the CPU through the
product's own loader; every test that needs a model reuses that one load. No generated string is compared with a literal. Assertions rest on
message roles, token counts, stop conditions, stream shape and the provider's own bookkeeping.

The module-level ``torch`` binding of the provider is ``None`` exactly when the optional import failed at import time. The tests put the
provider into that state by assigning ``None`` to the binding for the duration of one ``with`` block and restoring the original object in
``finally``. The same mechanism points the binding at real library objects that lack a usable ``cuda`` namespace to exercise the CUDA probes.
Private data attributes of provider instances (device flags, the loaded-model slot) are set directly to place a provider in a state that
needs hardware the container does not have.
"""

from __future__ import annotations

import asyncio
import dataclasses
import gc
import json
from contextlib import contextmanager
from typing import TYPE_CHECKING, Final, cast

import pytest
import torch
from transformers import AutoTokenizer

from intellicrack.core.types import (
    Message,
    ProviderCredentials,
    ProviderError,
    ThinkingConfig,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
    ToolResult,
)
from intellicrack.providers import local_transformers
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.model_loader import (
    RECOMMENDED_MODELS_B580,
    LoadedModel,
    ModelCache,
    ModelConfig,
    load_model_for_cpu,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Generator
    from pathlib import Path

    from transformers import PreTrainedTokenizerBase

    from intellicrack.providers.base import UsageInfo


_MODEL_ID: Final[str] = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
_USER_TEXT: Final[str] = "Say hello."
_SHORT_REPLY_TOKENS: Final[int] = 3
_CACHE_LIMIT_BYTES: Final[int] = 64 * 1024**3
_BYTES_PER_GIB: Final[int] = 2**30
_PLAIN_TEMPLATE: Final[str] = "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\n{% endfor %}assistant:"
_FAILING_TEMPLATE: Final[str] = "{{ messages[0]['content'] + 1 }}"
_HF_TOKEN_VARS: Final[tuple[str, ...]] = (
    "LOCAL_TRANSFORMERS_HF_TOKEN",
    "HUGGINGFACE_API_TOKEN",
    "HF_TOKEN",
    "HUGGINGFACE_HUB_TOKEN",
)


@contextmanager
def _binding_replaced(name: str, replacement: object) -> Generator[None]:
    """Point one module-level binding of the provider module at another object.

    Args:
        name: Name of the binding in ``intellicrack.providers.local_transformers``.
        replacement: Object to bind for the duration of the ``with`` block.

    Yields:
        None: Control while the replacement is bound; the original object is restored afterwards.
    """
    original = getattr(local_transformers, name)
    setattr(local_transformers, name, replacement)
    try:
        yield
    finally:
        setattr(local_transformers, name, original)


def _method(owner: object, name: str) -> Callable[..., object]:
    """Look up a provider-private callable with typing intact.

    Args:
        owner: The module, class or instance that owns the callable.
        name: Attribute name of the callable.

    Returns:
        Callable[..., object]: The bound or plain callable.
    """
    return cast("Callable[..., object]", getattr(owner, name))


def _private_state(owner: object) -> dict[str, object]:
    """Expose an instance's attribute dictionary for private-flag reads and writes.

    Args:
        owner: The instance whose attributes are needed.

    Returns:
        dict[str, object]: The live instance dictionary.
    """
    return cast("dict[str, object]", vars(owner))


def _user(text: str) -> list[Message]:
    """Build a one-message user conversation.

    Args:
        text: The user's message text.

    Returns:
        list[Message]: A single user message.
    """
    return [Message(role="user", content=text)]


def _provider_with(loaded: LoadedModel) -> LocalTransformersProvider:
    """Build a connected provider whose model slot already holds a real loaded model.

    Args:
        loaded: The real loaded model to place in the provider's model slot.

    Returns:
        LocalTransformersProvider: A provider with its own empty model cache.
    """
    provider = LocalTransformersProvider(model_cache=ModelCache())
    provider.connected = True
    _private_state(provider)["_loaded_model"] = loaded
    return provider


def _cache_with(loaded: LoadedModel) -> ModelCache:
    """Build a cache that answers a CPU load of ``loaded`` without loading anything again.

    The loaded model is registered under both the literal ``"auto"`` dtype the provider requests and its resolved dtype. Each entry is a
    copy of the dataclass that shares the one real model and tokenizer.

    Args:
        loaded: The real loaded model to register.

    Returns:
        ModelCache: A cache large enough that nothing is ever evicted.
    """
    cache = ModelCache(max_memory_bytes=_CACHE_LIMIT_BYTES)
    for dtype in ("auto", loaded.dtype):
        cache.put(dataclasses.replace(loaded, dtype=dtype))
    return cache


def _usage_of(provider: LocalTransformersProvider) -> UsageInfo:
    """Collect the usage record the last request left on a provider.

    Args:
        provider: The provider that served the request.

    Returns:
        UsageInfo: The pending usage record.
    """
    usage = provider.get_pending_usage()
    assert usage is not None
    return usage


def _fresh_tokenizer() -> PreTrainedTokenizerBase:
    """Load a new, independent copy of the baked model's tokenizer.

    Returns:
        PreTrainedTokenizerBase: A tokenizer no other test shares.
    """
    return AutoTokenizer.from_pretrained(_MODEL_ID)


def _plain_tokenizer() -> PreTrainedTokenizerBase:
    """Load a tokenizer whose chat template does not read the end-of-sequence token.

    Returns:
        PreTrainedTokenizerBase: A fresh tokenizer carrying a template that renders ``role: content`` lines.
    """
    tokenizer = _fresh_tokenizer()
    tokenizer.chat_template = _PLAIN_TEMPLATE
    return tokenizer


def _prompt_for(tokenizer: PreTrainedTokenizerBase, user_text: str) -> str:
    """Render the prompt a one-message conversation produces with a tokenizer's template.

    Args:
        tokenizer: The tokenizer whose chat template renders the prompt.
        user_text: The user's message text.

    Returns:
        str: The rendered prompt ending in the generation prompt.
    """
    rendered = tokenizer.apply_chat_template(
        [{"role": "user", "content": user_text}],
        tokenize=False,
        add_generation_prompt=True,
    )
    return str(rendered)


def _prompt_token_count(tokenizer: PreTrainedTokenizerBase, user_text: str) -> int:
    """Count the tokens of the prompt a one-message conversation produces.

    Args:
        tokenizer: The tokenizer that renders and encodes the prompt.
        user_text: The user's message text.

    Returns:
        int: The prompt length in tokens.
    """
    encoded = tokenizer(_prompt_for(tokenizer, user_text), return_tensors="pt", truncation=True)
    return int(encoded["input_ids"].shape[-1])


def _first_greedy_token(loaded: LoadedModel, tokenizer: PreTrainedTokenizerBase, user_text: str) -> int:
    """Compute, straight from the model, the token greedy decoding would emit first.

    Args:
        loaded: The real loaded model.
        tokenizer: The tokenizer that renders and encodes the prompt.
        user_text: The user's message text.

    Returns:
        int: The id of the highest-scoring first token.
    """
    encoded = tokenizer(_prompt_for(tokenizer, user_text), return_tensors="pt", truncation=True)
    with torch.inference_mode():
        output = loaded.model(
            input_ids=encoded["input_ids"],
            attention_mask=encoded.get("attention_mask"),
            use_cache=False,
        )
    logits = cast("torch.Tensor", output.logits)
    return int(logits[0, -1].argmax().item())


def _forced_eos_model(loaded: LoadedModel) -> LoadedModel:
    """Copy a loaded model so its end-of-sequence token is the token greedy decoding emits first.

    Args:
        loaded: The real loaded model.

    Returns:
        LoadedModel: A copy sharing the real model whose tokenizer treats the first greedy token as end-of-sequence.
    """
    first = _first_greedy_token(loaded, _plain_tokenizer(), _USER_TEXT)
    forced = _plain_tokenizer()
    forced.eos_token_id = first
    return dataclasses.replace(loaded, tokenizer=forced)


def _full_collections_during(action: Callable[[], object]) -> int:
    """Count the full garbage collections that start while ``action`` runs.

    Args:
        action: The callable to run.

    Returns:
        int: How many generation-2 collections started during the call.
    """
    started: list[int] = []

    def _record(phase: str, info: dict[str, int]) -> None:
        """Remember the generation of every collection that starts.

        Args:
            phase: ``"start"`` or ``"stop"``.
            info: The collector's description of the collection.
        """
        if phase == "start":
            started.append(info["generation"])

    gc.callbacks.append(_record)
    try:
        action()
    finally:
        gc.callbacks.remove(_record)
    return started.count(2)


def _binary_tool() -> ToolDefinition:
    """Build a real tool definition for binary analysis function calling.

    Returns:
        ToolDefinition: A definition exposing ``binary.get_file_size``.
    """
    return ToolDefinition(
        tool_name=ToolName.GHIDRA.value,
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
    )


@pytest.fixture(scope="module")
def loaded_model() -> Generator[LoadedModel]:
    """Load the baked model once for the whole file and release it afterwards.

    Yields:
        LoadedModel: The real model and tokenizer on the CPU, loaded through the product's loader.
    """
    loaded = load_model_for_cpu(ModelConfig(model_id=_MODEL_ID, dtype="auto", device="cpu"))
    yield loaded
    del loaded
    gc.collect()


def test_resolve_hf_token_prefers_the_explicit_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """A token supplied by the caller wins over every token in the environment.

    Args:
        monkeypatch: Sets all four environment variables to distinct values.
    """
    for name in _HF_TOKEN_VARS:
        monkeypatch.setenv(name, f"value-of-{name}")

    assert _method(local_transformers, "_resolve_hf_token")("explicit-value") == "explicit-value"


def test_resolve_hf_token_walks_the_environment_in_priority_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without an explicit token the first non-empty variable of the priority list is used.

    Args:
        monkeypatch: Clears and sets the four environment variables one at a time.
    """
    resolve = _method(local_transformers, "_resolve_hf_token")
    for name in _HF_TOKEN_VARS:
        monkeypatch.delenv(name, raising=False)
    assert resolve() is None

    for name in reversed(_HF_TOKEN_VARS):
        monkeypatch.setenv(name, f"value-of-{name}")
        assert resolve() == f"value-of-{name}"

    monkeypatch.setenv(_HF_TOKEN_VARS[0], "")
    assert resolve() == f"value-of-{_HF_TOKEN_VARS[1]}"


def test_dialect_is_none_and_device_flags_are_exposed() -> None:
    """The provider has no wire dialect and reports its private device flags through properties."""
    provider = LocalTransformersProvider(model_cache=ModelCache())

    assert provider.dialect is None
    assert provider.cuda_available is False
    assert provider.is_b580_detected is False

    state = _private_state(provider)
    state["_cuda_available"] = True
    state["_is_arc_b580"] = True

    assert provider.cuda_available is True
    assert provider.is_b580_detected is True


@pytest.mark.asyncio
async def test_connect_without_torch_raises_provider_error() -> None:
    """Connecting without torch is refused and leaves the provider disconnected."""
    provider = LocalTransformersProvider(model_cache=ModelCache())

    with _binding_replaced("_torch", None), pytest.raises(ProviderError, match="torch is required"):
        await provider.connect(ProviderCredentials())

    assert provider.connected is False


def test_cuda_probes_report_nothing_when_torch_is_missing() -> None:
    """With no torch the CUDA probe is false and the device count is zero."""
    with _binding_replaced("_torch", None):
        assert _method(LocalTransformersProvider, "_probe_cuda")() is False
        assert _method(LocalTransformersProvider, "_cuda_device_count")() == 0


def test_cuda_probes_report_nothing_without_a_cuda_namespace() -> None:
    """A torch-like module without a ``cuda`` namespace yields a false probe and a zero count."""
    with _binding_replaced("_torch", json):
        assert _method(LocalTransformersProvider, "_probe_cuda")() is False
        assert _method(LocalTransformersProvider, "_cuda_device_count")() == 0


def test_cuda_probes_survive_a_broken_cuda_namespace() -> None:
    """A ``cuda`` attribute that lacks ``is_available`` and ``device_count`` is treated as no CUDA, not an error."""
    with _binding_replaced("_torch", torch.nn.Module):
        assert _method(LocalTransformersProvider, "_probe_cuda")() is False
        assert _method(LocalTransformersProvider, "_cuda_device_count")() == 0


def test_release_device_caches_on_cuda_runs_a_full_collection() -> None:
    """Releasing caches on a CUDA-selected provider without CUDA still finishes with a full collection."""
    provider = LocalTransformersProvider(model_cache=ModelCache())
    _private_state(provider)["_device_type"] = "cuda"

    assert _full_collections_during(_method(provider, "_release_device_caches")) >= 1


def test_release_device_caches_survives_a_broken_cuda_namespace() -> None:
    """A failing CUDA allocator probe is absorbed and the full collection still runs."""
    provider = LocalTransformersProvider(model_cache=ModelCache())
    _private_state(provider)["_device_type"] = "cuda"

    with _binding_replaced("_torch", torch.nn.Module):
        collections = _full_collections_during(_method(provider, "_release_device_caches"))

    assert collections >= 1


@pytest.mark.asyncio
async def test_list_models_on_xpu_without_vram_data_excludes_nothing() -> None:
    """With no VRAM figure an XPU-selected provider still lists every recommended model."""
    provider = LocalTransformersProvider(model_cache=ModelCache())
    provider.connected = True
    _private_state(provider)["_device_type"] = "xpu"

    models = await provider.list_models()

    assert [model.id for model in models] == [str(entry["model_id"]) for entry in RECOMMENDED_MODELS_B580]


@pytest.mark.asyncio
async def test_chat_reports_load_failure_for_an_unloadable_model(tmp_path: Path) -> None:
    """A model directory with no checkpoint fails to load and, with no fallback device, surfaces as a provider error.

    Args:
        tmp_path: An empty directory used as the model id.
    """
    provider = LocalTransformersProvider(model_cache=ModelCache())
    provider.connected = True

    with pytest.raises(ProviderError, match="Failed to load model") as excinfo:
        await provider.chat(_user("hi"), model=str(tmp_path))

    assert str(tmp_path) in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert provider.current_model_id is None
    assert provider.device_type == "cpu"


@pytest.mark.asyncio
async def test_chat_stream_requires_connection() -> None:
    """Streaming from a provider that never connected is refused."""
    provider = LocalTransformersProvider(model_cache=ModelCache())
    stream = provider.chat_stream(_user("hi"), model=_MODEL_ID)

    with pytest.raises(ProviderError, match="Provider not connected"):
        await anext(stream)


@pytest.mark.asyncio
async def test_load_failure_on_every_device_reports_all_devices_failed(tmp_path: Path) -> None:
    """A CUDA provider falls back to the CPU, and when the CPU load fails too the error names every attempted device.

    Args:
        tmp_path: An empty directory used as the model id.
    """
    provider = LocalTransformersProvider(model_cache=ModelCache())
    provider.connected = True
    _private_state(provider)["_device_type"] = "cuda"

    with pytest.raises(ProviderError, match="all attempted devices") as excinfo:
        await provider.chat(_user("hi"), model=str(tmp_path))

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert provider.device_type == "cpu"
    assert provider.current_model_id is None


def test_fallback_chain_per_device() -> None:
    """CUDA and XPU fall back to the CPU, and the CPU has nothing left to fall back to."""
    chain = _method(LocalTransformersProvider, "_fallback_chain_for")

    assert chain("cuda") == ["cpu"]
    assert chain("xpu") == ["cpu"]
    assert chain("cpu") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failing_device", ["cuda", "xpu"])
async def test_load_failure_falls_back_to_cpu_and_chat_completes(loaded_model: LoadedModel, failing_device: str) -> None:
    """When the selected accelerator cannot load the model the provider switches to the CPU and still answers.

    Args:
        loaded_model: The real model, served to the CPU loader through a cache.
        failing_device: The accelerator the provider starts on; the container has neither.
    """
    provider = LocalTransformersProvider(model_cache=_cache_with(loaded_model))
    provider.connected = True
    _private_state(provider)["_device_type"] = failing_device

    message, tool_calls = await provider.chat(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=2)

    assert provider.device_type == "cpu"
    assert provider.current_model_id == _MODEL_ID
    assert message.role == "assistant"
    assert tool_calls is None
    usage = _usage_of(provider)
    assert usage.prompt_tokens == _prompt_token_count(loaded_model.tokenizer, _USER_TEXT)
    assert 1 <= usage.completion_tokens <= 2
    assert usage.total_tokens == usage.prompt_tokens + usage.completion_tokens


def test_generate_sync_without_a_model_raises_runtime_error() -> None:
    """Generating with no model in the slot is a runtime error."""
    provider = LocalTransformersProvider(model_cache=ModelCache())

    with pytest.raises(RuntimeError, match="No model loaded"):
        _method(provider, "_generate_sync")("prompt", 0.0, 1)


@pytest.mark.asyncio
async def test_stream_generate_without_a_model_raises_runtime_error() -> None:
    """Streaming generation with no model in the slot is a runtime error on the first step."""
    provider = LocalTransformersProvider(model_cache=ModelCache())
    stream = cast("AsyncIterator[str]", _method(provider, "_stream_generate")("prompt", 0.0, 1))

    with pytest.raises(RuntimeError, match="No model loaded"):
        await anext(stream)


@pytest.mark.asyncio
async def test_chat_wraps_missing_torch_in_provider_error(loaded_model: LoadedModel) -> None:
    """Without torch, a chat on a loaded provider fails as a provider error caused by an import error and records no usage.

    Args:
        loaded_model: The real model placed in the provider's model slot.
    """
    provider = _provider_with(loaded_model)

    with _binding_replaced("_torch", None), pytest.raises(ProviderError, match="Local inference failed") as excinfo:
        await provider.chat(_user(_USER_TEXT), model=_MODEL_ID, max_tokens=1)

    assert isinstance(excinfo.value.__cause__, ImportError)
    assert provider.get_pending_usage() is None


@pytest.mark.asyncio
async def test_chat_stream_wraps_missing_torch_in_provider_error(loaded_model: LoadedModel) -> None:
    """Without torch, streaming from a loaded provider fails as a provider error caused by an import error.

    Args:
        loaded_model: The real model placed in the provider's model slot.
    """
    provider = _provider_with(loaded_model)
    stream = provider.chat_stream(_user(_USER_TEXT), model=_MODEL_ID, max_tokens=1)

    with _binding_replaced("_torch", None), pytest.raises(ProviderError, match="Local streaming failed") as excinfo:
        await anext(stream)

    assert isinstance(excinfo.value.__cause__, ImportError)


@pytest.mark.asyncio
async def test_generation_loop_requires_torch(loaded_model: LoadedModel) -> None:
    """The decoding loop refuses to start without torch and generates nothing.

    The forward-pass argument is never called: the loop checks for torch before its first step.

    Args:
        loaded_model: Supplies the real model and tokenizer arguments.
    """
    provider = _provider_with(loaded_model)
    counter = [0]
    loop = cast(
        "AsyncIterator[str]",
        _method(provider, "_iter_local_generation_loop")(
            model=loaded_model.model,
            tokenizer=loaded_model.tokenizer,
            generated_ids=torch.tensor([[1]]),
            attention_mask=None,
            past_key_values=None,
            max_tokens=1,
            temperature=0.0,
            forward_pass=loaded_model.model,
            completion_counter=counter,
        ),
    )

    with _binding_replaced("_torch", None), pytest.raises(ImportError, match="torch is required"):
        await anext(loop)

    assert counter == [0]


@pytest.mark.asyncio
async def test_chat_stream_wraps_failure_after_first_chunk(loaded_model: LoadedModel) -> None:
    """Losing torch between two steps of a stream surfaces as a provider error and the usage keeps the tokens already produced.

    Args:
        loaded_model: The real model placed in the provider's model slot.
    """
    provider = _provider_with(loaded_model)
    stream = provider.chat_stream(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=8)

    assert await anext(stream)
    with _binding_replaced("_torch", None), pytest.raises(ProviderError, match="Local streaming failed") as excinfo:
        await anext(stream)

    assert isinstance(excinfo.value.__cause__, ImportError)
    usage = _usage_of(provider)
    assert usage.prompt_tokens == _prompt_token_count(loaded_model.tokenizer, _USER_TEXT)
    assert usage.completion_tokens >= 1
    assert usage.total_tokens == usage.prompt_tokens + usage.completion_tokens


@pytest.mark.asyncio
async def test_chat_stream_stops_after_cancel_between_chunks(loaded_model: LoadedModel) -> None:
    """Cancelling after the first chunk ends the stream cleanly before the token budget is spent.

    Args:
        loaded_model: The real model placed in the provider's model slot.
    """
    provider = _provider_with(loaded_model)
    max_tokens = 8
    chunks: list[str] = []

    async for chunk in provider.chat_stream(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=max_tokens):
        chunks.append(chunk)
        await provider.cancel_request()

    assert len(chunks) == 1
    usage = _usage_of(provider)
    assert 1 <= usage.completion_tokens < max_tokens


@pytest.mark.asyncio
async def test_chat_stream_cancelled_before_the_first_chunk_yields_nothing(loaded_model: LoadedModel) -> None:
    """A cancel that lands while the first token is being computed suppresses that token.

    Args:
        loaded_model: The real model placed in the provider's model slot.
    """
    provider = _provider_with(loaded_model)
    canceller = asyncio.create_task(provider.cancel_request())

    chunks = [chunk async for chunk in provider.chat_stream(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=4)]
    await canceller
    for _ in range(3):
        await asyncio.sleep(0)

    assert chunks == []


@pytest.mark.asyncio
async def test_chat_stream_failure_after_cancel_is_swallowed(loaded_model: LoadedModel) -> None:
    """An error raised after the caller cancelled ends the stream quietly instead of raising.

    The cancel lands while the model is being fetched from the cache, then the missing torch makes generation fail.

    Args:
        loaded_model: The real model, served to the CPU loader through a cache.
    """
    provider = LocalTransformersProvider(model_cache=_cache_with(loaded_model))
    provider.connected = True
    canceller = asyncio.create_task(provider.cancel_request())

    with _binding_replaced("_torch", None):
        chunks = [chunk async for chunk in provider.chat_stream(_user(_USER_TEXT), model=_MODEL_ID, max_tokens=2)]
    await canceller

    assert chunks == []
    assert provider.current_model_id == _MODEL_ID


@pytest.mark.asyncio
async def test_chat_stops_at_the_end_of_sequence_token(loaded_model: LoadedModel) -> None:
    """Generation ends on the end-of-sequence token and the usage counts exactly that one completion token.

    Args:
        loaded_model: The real model, wrapped with a tokenizer whose end-of-sequence token is the first greedy token.
    """
    provider = _provider_with(_forced_eos_model(loaded_model))

    message, _ = await provider.chat(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=4)

    assert message.role == "assistant"
    usage = _usage_of(provider)
    assert usage.prompt_tokens == _prompt_token_count(_plain_tokenizer(), _USER_TEXT)
    assert usage.completion_tokens == 1


@pytest.mark.asyncio
async def test_stream_stops_at_the_end_of_sequence_token(loaded_model: LoadedModel) -> None:
    """A stream whose first token is the end-of-sequence token yields nothing and counts no completion tokens.

    Args:
        loaded_model: The real model, wrapped with a tokenizer whose end-of-sequence token is the first greedy token.
    """
    provider = _provider_with(_forced_eos_model(loaded_model))

    chunks = [chunk async for chunk in provider.chat_stream(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=4)]

    assert chunks == []
    usage = _usage_of(provider)
    assert usage.prompt_tokens == _prompt_token_count(_plain_tokenizer(), _USER_TEXT)
    assert usage.completion_tokens == 0


@pytest.mark.asyncio
async def test_chat_without_attention_mask_matches_masked_chat(loaded_model: LoadedModel) -> None:
    """A tokenizer that returns no attention mask yields the same greedy reply and usage as one that does.

    Args:
        loaded_model: The real model; one provider uses its own tokenizer, the other a tokenizer without a mask.
    """
    unmasked_tokenizer = _fresh_tokenizer()
    _private_state(unmasked_tokenizer)["model_input_names"] = ["input_ids"]
    assert unmasked_tokenizer("probe", return_tensors="pt").get("attention_mask") is None

    masked_provider = _provider_with(loaded_model)
    masked_message, _ = await masked_provider.chat(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=_SHORT_REPLY_TOKENS)
    unmasked_provider = _provider_with(dataclasses.replace(loaded_model, tokenizer=unmasked_tokenizer))
    unmasked_message, _ = await unmasked_provider.chat(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=_SHORT_REPLY_TOKENS)

    assert unmasked_message.content == masked_message.content
    assert _usage_of(unmasked_provider) == _usage_of(masked_provider)


@pytest.mark.asyncio
async def test_stream_without_attention_mask_still_streams(loaded_model: LoadedModel) -> None:
    """A tokenizer that returns no attention mask still produces a stream with consistent usage.

    Args:
        loaded_model: The real model, wrapped with a tokenizer that returns no attention mask.
    """
    unmasked_tokenizer = _fresh_tokenizer()
    _private_state(unmasked_tokenizer)["model_input_names"] = ["input_ids"]
    provider = _provider_with(dataclasses.replace(loaded_model, tokenizer=unmasked_tokenizer))

    chunks = [
        chunk async for chunk in provider.chat_stream(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=_SHORT_REPLY_TOKENS)
    ]

    usage = _usage_of(provider)
    assert chunks
    assert usage.prompt_tokens == _prompt_token_count(loaded_model.tokenizer, _USER_TEXT)
    assert len(chunks) <= usage.completion_tokens <= _SHORT_REPLY_TOKENS


@pytest.mark.asyncio
async def test_chat_ignores_tool_choice_thinking_and_cache_options(loaded_model: LoadedModel) -> None:
    """Tool-choice, thinking and cache options are ignored locally: the greedy reply and usage do not change.

    Args:
        loaded_model: The real model placed in each provider's model slot.
    """
    plain_provider = _provider_with(loaded_model)
    plain_message, _ = await plain_provider.chat(_user(_USER_TEXT), model=_MODEL_ID, temperature=0.0, max_tokens=_SHORT_REPLY_TOKENS)
    option_provider = _provider_with(loaded_model)

    option_message, option_calls = await option_provider.chat(
        _user(_USER_TEXT),
        model=_MODEL_ID,
        temperature=0.0,
        max_tokens=_SHORT_REPLY_TOKENS,
        tool_choice=ToolChoice(mode=ToolChoiceMode.REQUIRED),
        thinking=ThinkingConfig(enabled=True),
        enable_cache=True,
    )

    assert option_calls is None
    assert option_message.content == plain_message.content
    assert _usage_of(option_provider) == _usage_of(plain_provider)


@pytest.mark.asyncio
async def test_chat_stream_ignores_tool_choice_thinking_and_cache_options(loaded_model: LoadedModel) -> None:
    """Tool-choice, thinking and cache options are ignored locally: the greedy stream and usage do not change.

    Args:
        loaded_model: The real model placed in each provider's model slot.
    """
    plain_provider = _provider_with(loaded_model)
    plain_chunks = [
        chunk
        async for chunk in plain_provider.chat_stream(
            _user(_USER_TEXT),
            model=_MODEL_ID,
            temperature=0.0,
            max_tokens=_SHORT_REPLY_TOKENS,
        )
    ]
    option_provider = _provider_with(loaded_model)

    option_chunks = [
        chunk
        async for chunk in option_provider.chat_stream(
            _user(_USER_TEXT),
            model=_MODEL_ID,
            temperature=0.0,
            max_tokens=_SHORT_REPLY_TOKENS,
            tool_choice=ToolChoice(mode=ToolChoiceMode.REQUIRED),
            thinking=ThinkingConfig(enabled=True),
            enable_cache=True,
        )
    ]

    assert option_chunks == plain_chunks
    assert _usage_of(option_provider) == _usage_of(plain_provider)


@pytest.mark.asyncio
async def test_chat_with_tools_but_no_tool_call_returns_none(loaded_model: LoadedModel) -> None:
    """A short reply that contains no tool-call object yields no tool calls, and the tool schema was added to the prompt.

    Args:
        loaded_model: The real model placed in the provider's model slot.
    """
    provider = _provider_with(loaded_model)

    message, tool_calls = await provider.chat(
        _user(_USER_TEXT),
        model=_MODEL_ID,
        tools=[_binary_tool()],
        temperature=0.0,
        max_tokens=_SHORT_REPLY_TOKENS,
    )

    assert tool_calls is None
    assert message.tool_calls is None
    assert message.role == "assistant"
    assert _usage_of(provider).prompt_tokens > _prompt_token_count(loaded_model.tokenizer, _USER_TEXT)


@pytest.mark.asyncio
async def test_chat_stream_with_tools_but_no_tool_call_leaves_no_pending_calls(loaded_model: LoadedModel) -> None:
    """A streamed reply with tools offered but no tool-call object leaves no pending tool calls.

    Args:
        loaded_model: The real model placed in the provider's model slot.
    """
    provider = _provider_with(loaded_model)

    chunks = [
        chunk
        async for chunk in provider.chat_stream(
            _user(_USER_TEXT),
            model=_MODEL_ID,
            tools=[_binary_tool()],
            temperature=0.0,
            max_tokens=_SHORT_REPLY_TOKENS,
        )
    ]

    assert chunks
    assert provider.get_pending_tool_calls() == []
    assert _usage_of(provider).prompt_tokens > _prompt_token_count(loaded_model.tokenizer, _USER_TEXT)


def test_format_prompt_falls_back_to_chatml_when_the_template_raises(loaded_model: LoadedModel) -> None:
    """A chat template that fails to render is replaced by the ChatML layout.

    Args:
        loaded_model: The real model; its tokenizer is swapped for one whose template raises.
    """
    failing = _fresh_tokenizer()
    failing.chat_template = _FAILING_TEMPLATE
    provider = _provider_with(dataclasses.replace(loaded_model, tokenizer=failing))

    prompt = _method(provider, "_format_prompt")([{"role": "user", "content": "ping"}], None)

    assert prompt == "<|im_start|>user\nping<|im_end|>\n<|im_start|>assistant\n"


def test_convert_messages_serializes_tool_results() -> None:
    """Tool results on a message are carried into the provider-format dictionary field by field."""
    provider = LocalTransformersProvider(model_cache=ModelCache())
    result = ToolResult(call_id="call_1", success=True, result="1148416", error=None, duration_ms=2.5)

    converted = provider.convert_messages_to_provider_format([Message(role="tool", content="", tool_results=[result])])

    assert converted == [
        {
            "role": "tool",
            "content": "",
            "tool_results": [{"call_id": "call_1", "result": "1148416", "success": True}],
        },
    ]


def test_build_chat_messages_skips_a_tool_message_without_results() -> None:
    """A tool message whose result list is empty contributes no turn to the chat."""
    provider = LocalTransformersProvider(model_cache=ModelCache())

    built = _method(provider, "_build_chat_messages")(
        [
            {"role": "user", "content": "q"},
            {"role": "tool", "content": "", "tool_results": []},
        ],
        None,
    )

    assert built == [{"role": "user", "content": "q"}]


def test_parse_tool_calls_rejects_balanced_but_invalid_json() -> None:
    """A tool-call object with balanced braces but invalid JSON parses to nothing, while the valid form parses."""
    parse = _method(LocalTransformersProvider, "_parse_tool_calls")

    assert parse('{"tool_call": {name: "x"}}') is None

    parsed = cast("list[object]", parse('{"tool_call": {"name": "x"}}'))
    assert len(parsed) == 1


def test_get_device_info_on_xpu_without_a_device_reports_zero_allocation() -> None:
    """An XPU-selected provider on a host with no XPU reports zero allocated memory and no device details."""
    provider = LocalTransformersProvider(model_cache=ModelCache())
    state = _private_state(provider)
    state["_device_type"] = "xpu"
    state["_xpu_available"] = True

    info = provider.get_device_info()

    assert info["device_type"] == "xpu"
    assert info["allocated_memory_gb"] == pytest.approx(0.0)
    assert "device_name" not in info
    assert "total_memory_gb" not in info
    assert "loaded_model" not in info


def test_get_device_info_reports_the_loaded_model(loaded_model: LoadedModel) -> None:
    """Device info names the loaded model, its dtype and its memory footprint in GiB.

    Args:
        loaded_model: The real model placed in the provider's model slot.
    """
    info = _provider_with(loaded_model).get_device_info()

    assert info["loaded_model"] == _MODEL_ID
    assert info["model_dtype"] == "float32"
    assert info["model_memory_gb"] == pytest.approx(loaded_model.memory_usage_bytes / _BYTES_PER_GIB)


def test_load_model_for_cuda_requires_torch() -> None:
    """Loading for CUDA without torch is an import error."""
    provider = LocalTransformersProvider(model_cache=ModelCache())

    with _binding_replaced("_torch", None), pytest.raises(ImportError, match="torch is required"):
        _method(provider, "_load_model_for_cuda")(ModelConfig(model_id=_MODEL_ID))
