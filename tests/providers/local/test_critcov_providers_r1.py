# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass critical-coverage tests for the XPU utilities, model loader, local transformers provider and Ollama provider.

Four groups of lines that the first pass left are reached with real objects:

* The torch handle of ``xpu_utils`` is pointed at real library objects that lack a usable ``xpu`` namespace, which are the states of an old
  PyTorch build and of a build whose ``xpu`` attribute is not a namespace.
* The model loader's tolerance of a checkpoint folder whose listing is refused by the operating system, produced with a real access-control
  entry on a real directory.
* The local transformers provider is driven with a tiny real ``LlamaForCausalLM`` whose weights are set so that greedy decoding always emits
  one chosen token, and a real ``tokenizers`` word-level vocabulary that decodes that token to a reply containing a tool call.
* The Ollama provider's connect probes are interrupted by a disconnect while the loopback server is holding the reply.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
import torch
from tokenizers import Tokenizer
from transformers import LlamaConfig, LlamaForCausalLM

from intellicrack.core.types import (
    Message,
    ProviderCredentials,
    ProviderError,
    ToolDefinition,
    ToolFunction,
    ToolParameter,
)
from intellicrack.providers import xpu_utils
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.model_loader import LoadedModel, ModelCache, validate_local_checkpoint
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.xpu_utils import (
    get_xpu_device_count,
    get_xpu_device_info,
    get_xpu_memory_info,
    initialize_xpu,
    is_xpu_available,
)
from tests._helpers.scripted_http_server import RecordedRequest, ScriptedHttpServer, ScriptedResponse, json_response


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterable
    from types import ModuleType

    from transformers import PreTrainedModel, PreTrainedTokenizerBase


_WAIT_SECONDS: Final[float] = 10.0
_TAGS: Final[str] = "/api/tags"
_CHAT: Final[str] = "/api/chat"
_KEY: Final[str] = "loopback-cloud-credential"
_EVERYONE_SID: Final[str] = "*S-1-1-0"
_ICACLS_TIMEOUT_SECONDS: Final[float] = 30.0
_TOOL_TOKEN_ID: Final[int] = 3
_TOOL_REPLY: Final[str] = 'Checking now. {"tool_call": {"name": "ghidra.decompile", "arguments": {"address": "0x401000"}}}'
_TOOL_MODEL_ID: Final[str] = "intellicrack/tool-caller-fixture"


@contextmanager
def _binding_replaced(owner: ModuleType, name: str, replacement: object) -> Generator[None]:
    """Point one module-level binding at another object for the duration of a ``with`` block.

    Args:
        owner: The module that holds the binding.
        name: Name of the binding.
        replacement: Object to bind while the block runs.

    Yields:
        None: Control while the replacement is bound; the original object is restored afterwards.
    """
    original = getattr(owner, name)
    setattr(owner, name, replacement)
    try:
        yield
    finally:
        setattr(owner, name, original)


def _extract_torch_xpu_properties(torch_like: object, device_index: int, device_name: str) -> tuple[int, str, str]:
    """Call the module-private ``_extract_torch_xpu_properties``.

    Args:
        torch_like: The object passed as the ``torch`` argument.
        device_index: Device index to look up.
        device_name: Best-known device name.

    Returns:
        tuple[int, str, str]: ``(total_memory, driver_version, device_name)``.
    """
    fn = cast("Callable[[object, int, str], tuple[int, str, str]]", vars(xpu_utils)["_extract_torch_xpu_properties"])
    return fn(torch_like, device_index, device_name)


def test_torch_without_an_xpu_namespace_is_reported_unavailable() -> None:
    """A torch handle with no ``xpu`` attribute is not available, and initialization says the XPU namespace is missing.

    One-line change that fails it: change ``not hasattr(torch, "xpu")`` to ``hasattr(torch, "xpu")`` at xpu_utils.py:99.
    """
    with _binding_replaced(xpu_utils, "_torch_module", json):
        assert is_xpu_available() is False
        with pytest.raises(RuntimeError, match="PyTorch XPU support is not available"):
            initialize_xpu(0)


def test_broken_xpu_namespace_degrades_every_probe_to_its_neutral_value() -> None:
    """A torch whose ``xpu`` attribute has no ``is_available`` yields False, zero, None and the zero pair, not an error.

    ``torch.nn.Module.xpu`` is a method, so reading ``is_available`` from it raises ``AttributeError``.

    One-line change that fails it: remove ``AttributeError`` from the ``except`` tuple at xpu_utils.py:104.
    """
    with _binding_replaced(xpu_utils, "_torch_module", torch.nn.Module):
        assert is_xpu_available() is False
        assert get_xpu_device_count() == 0
        assert get_xpu_device_info(0) is None
        assert get_xpu_memory_info(0) == (0, 0)


def test_properties_without_a_properties_getter_keep_the_incoming_name() -> None:
    """A namespace with no ``get_device_properties`` leaves memory at zero, the driver empty and the name unchanged.

    One-line change that fails it: change ``not hasattr(torch.xpu, "get_device_properties")`` to ``hasattr(...)`` at xpu_utils.py:297.
    """
    assert _extract_torch_xpu_properties(torch.nn.Module, 0, "Known Adapter") == (0, "", "Known Adapter")


@contextmanager
def _listing_denied(directory: Path) -> Generator[None]:
    """Deny the ``read data`` right of Everyone on a directory, then remove the entry again.

    Args:
        directory: The directory whose listing is refused inside the block.

    Yields:
        None: Control while listing the directory fails.
    """
    icacls = str(Path(os.environ["SYSTEMROOT"]) / "System32" / "icacls.exe")
    _ = subprocess.run(
        [icacls, str(directory), "/deny", f"{_EVERYONE_SID}:(RD)"],
        capture_output=True,
        text=True,
        check=True,
        timeout=_ICACLS_TIMEOUT_SECONDS,
    )
    try:
        yield
    finally:
        _ = subprocess.run(
            [icacls, str(directory), "/remove:d", _EVERYONE_SID],
            capture_output=True,
            text=True,
            check=True,
            timeout=_ICACLS_TIMEOUT_SECONDS,
        )


@pytest.mark.spawns_process
def test_checkpoint_directory_that_cannot_be_listed_is_tolerated(tmp_path: Path) -> None:
    """A model folder the operating system refuses to list is skipped instead of failing the validation.

    The first assertion proves the precondition: the folder really cannot be listed.

    One-line change that fails it: change ``except OSError`` to ``except FileNotFoundError`` at model_loader.py:179.

    Args:
        tmp_path: Parent of the folder that gets the deny entry.
    """
    locked = tmp_path / "locked"
    locked.mkdir()
    with _listing_denied(locked):
        with pytest.raises(PermissionError):
            _ = list(locked.iterdir())
        validate_local_checkpoint(str(locked))


def _tool_caller() -> LoadedModel:
    """Build a tiny real causal language model that always emits one token, and a vocabulary that decodes it to a tool call.

    Every weight is zero except the embeddings (all ones), the normalization scales (all ones) and one row of the output projection (all
    ones). The residual stream therefore carries the embedding unchanged, and the logit of the chosen row is the largest for any input.

    Returns:
        LoadedModel: The model and tokenizer on the CPU.
    """
    vocabulary = {"<unk>": 0, "</s>": 1, "<pad>": 2, _TOOL_REPLY: _TOOL_TOKEN_ID}
    word_level = cast("Any", importlib.import_module("tokenizers.models")).WordLevel
    whitespace_split = cast("Any", importlib.import_module("tokenizers.pre_tokenizers")).WhitespaceSplit
    fast_tokenizer = cast("Any", importlib.import_module("transformers.tokenization_utils_tokenizers")).PreTrainedTokenizerFast
    backend = Tokenizer(word_level(vocabulary, unk_token="<unk>"))
    backend.pre_tokenizer = whitespace_split()
    tokenizer = fast_tokenizer(
        tokenizer_object=backend,
        unk_token="<unk>",
        eos_token="</s>",
        pad_token="<pad>",
        model_max_length=48,
        clean_up_tokenization_spaces=False,
    )
    config = LlamaConfig(
        vocab_size=len(vocabulary),
        hidden_size=8,
        intermediate_size=16,
        num_hidden_layers=1,
        num_attention_heads=2,
        num_key_value_heads=2,
        max_position_embeddings=128,
        tie_word_embeddings=False,
    )
    model = cast("PreTrainedModel", LlamaForCausalLM(config))
    parameters = cast("Iterable[tuple[str, torch.Tensor]]", cast("Any", model).named_parameters())
    with torch.no_grad():
        for name, parameter in parameters:
            _ = parameter.zero_()
            if name.endswith(("embed_tokens.weight", "norm.weight")):
                _ = parameter.fill_(1.0)
            elif name == "lm_head.weight":
                _ = parameter[_TOOL_TOKEN_ID].fill_(1.0)
    _ = cast("Any", model).eval()
    return LoadedModel(
        model=model,
        tokenizer=cast("PreTrainedTokenizerBase", tokenizer),
        device=torch.device("cpu"),
        dtype="float32",
        memory_usage_bytes=0,
        model_id=_TOOL_MODEL_ID,
        load_time_seconds=0.0,
    )


def _provider_with(loaded: LoadedModel) -> LocalTransformersProvider:
    """Build a connected provider whose model slot already holds a real loaded model.

    Args:
        loaded: The real loaded model to place in the provider's model slot.

    Returns:
        LocalTransformersProvider: A provider with its own empty model cache.
    """
    provider = LocalTransformersProvider(model_cache=ModelCache())
    provider.connected = True
    cast("dict[str, object]", vars(provider))["_loaded_model"] = loaded
    return provider


def _decompile_tool() -> ToolDefinition:
    """Build a real tool definition with one function.

    Returns:
        ToolDefinition: A definition exposing ``ghidra.decompile``.
    """
    return ToolDefinition(
        tool_name="ghidra",
        description="Ghidra analysis tools",
        functions=[
            ToolFunction(
                name="ghidra.decompile",
                description="Decompile the function at an address",
                parameters=[ToolParameter(name="address", type="string", description="Function address", required=True)],
                returns="Decompiled C source",
            ),
        ],
    )


def _ask() -> list[Message]:
    """Build a one-message conversation.

    Returns:
        list[Message]: A single user message.
    """
    return [Message(role="user", content="Decompile main.")]


@pytest.mark.asyncio
async def test_disconnect_releases_the_loaded_model() -> None:
    """Disconnecting a provider that holds a model empties the model slot and leaves it disconnected.

    One-line change that fails it: delete ``self._loaded_model = None`` at local_transformers.py:463.
    """
    provider = _provider_with(_tool_caller())
    assert provider.current_model_id == _TOOL_MODEL_ID

    await provider.disconnect()

    assert provider.current_model_id is None
    assert provider.connected is False


@pytest.mark.asyncio
async def test_chat_returns_the_tool_call_and_only_the_text_before_it() -> None:
    """A reply made of prose followed by a tool-call object yields the call and keeps just the prose as content.

    One-line change that fails it: delete the ``response_text = self._extract_text_before_tool_call(response_text)`` assignment at
    local_transformers.py:695, which leaves the JSON in the message text.
    """
    provider = _provider_with(_tool_caller())

    message, tool_calls = await provider.chat(_ask(), model=_TOOL_MODEL_ID, tools=[_decompile_tool()], temperature=0.0, max_tokens=1)

    assert message.content == "Checking now."
    assert tool_calls is not None
    assert [(call.tool_name, call.function_name, call.arguments) for call in tool_calls] == [
        ("ghidra", "ghidra.decompile", {"address": "0x401000"}),
    ]
    assert message.tool_calls == tool_calls


@pytest.mark.asyncio
async def test_chat_stream_publishes_the_tool_call_found_in_the_streamed_text() -> None:
    """A streamed reply containing a tool-call object leaves that call pending once the stream ends.

    One-line change that fails it: delete ``self._pending_tool_calls = parsed_calls`` at local_transformers.py:834.
    """
    provider = _provider_with(_tool_caller())

    chunks = [
        chunk
        async for chunk in provider.chat_stream(_ask(), model=_TOOL_MODEL_ID, tools=[_decompile_tool()], temperature=0.0, max_tokens=1)
    ]

    assert "".join(chunks) == _TOOL_REPLY
    pending = provider.get_pending_tool_calls()
    assert [(call.tool_name, call.function_name, call.arguments) for call in pending] == [
        ("ghidra", "ghidra.decompile", {"address": "0x401000"}),
    ]


def _gated_tags(arrived: threading.Event, gate: threading.Event) -> Callable[[RecordedRequest], ScriptedResponse]:
    """Build a ``/api/tags`` handler that announces the request and then holds its body until a gate opens.

    Args:
        arrived: Set as soon as the request reaches the server.
        gate: The body is written only after this event is set.

    Returns:
        Callable[[RecordedRequest], ScriptedResponse]: The handler.
    """

    def _reply(request: RecordedRequest) -> ScriptedResponse:
        """Answer one probe.

        Args:
            request: The received request.

        Returns:
            ScriptedResponse: An empty model listing gated on ``gate``.
        """
        del request
        arrived.set()
        return ScriptedResponse(chunks=(b'{"models": []}',), gates={0: gate})

    return _reply


def _cloud_provider(cloud_url: str) -> OllamaProvider:
    """Build a provider whose Ollama cloud endpoint is ``cloud_url``.

    Args:
        cloud_url: Base URL of the loopback server standing in for the cloud.

    Returns:
        OllamaProvider: A provider that treats ``cloud_url`` as ``CLOUD_API_URL``.
    """

    class _LoopbackCloudOllama(OllamaProvider):
        """OllamaProvider whose cloud endpoint is a loopback server."""

        CLOUD_API_URL = cloud_url

    return _LoopbackCloudOllama()


async def _disconnect_during_probe(
    provider: OllamaProvider,
    credentials: ProviderCredentials,
    arrived: threading.Event,
    gate: threading.Event,
) -> None:
    """Start a connect, disconnect while the held probe is in flight, and require the connect to fail.

    Args:
        provider: The provider to connect.
        credentials: Credentials for the connect.
        arrived: Set by the server when the held probe arrives.
        gate: Opened afterwards so the server can finish.
    """
    connect_task = asyncio.create_task(provider.connect(credentials))
    try:
        assert await asyncio.to_thread(arrived.wait, _WAIT_SECONDS)
        await provider.disconnect()
        with pytest.raises(ProviderError):
            await connect_task
    finally:
        gate.set()
        _ = await asyncio.gather(connect_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_disconnect_while_the_local_probe_is_in_flight_leaves_no_client() -> None:
    """A disconnect that closes the client during the local probe makes the probe fail without touching the absent client.

    One-line change that fails it: remove the ``if self._local_client:`` guard at ollama.py:335, which then calls ``aclose`` on ``None``.
    """
    arrived = threading.Event()
    gate = threading.Event()
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, _gated_tags(arrived, gate))
        provider = OllamaProvider()
        await _disconnect_during_probe(provider, ProviderCredentials(api_base=local.origin), arrived, gate)

    assert provider.connected is False
    assert provider.local_available is False
    assert getattr(provider, "_local_client") is None


@pytest.mark.asyncio
async def test_disconnect_while_the_cloud_probe_is_in_flight_leaves_no_client() -> None:
    """A disconnect that closes the client during the cloud probe makes the probe fail without touching the absent client.

    One-line change that fails it: remove the ``if self._cloud_client:`` guard at ollama.py:366, which then calls ``aclose`` on ``None``.
    """
    arrived = threading.Event()
    gate = threading.Event()
    with ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script("GET", _TAGS, json_response(500, {"error": "daemon down"}))
        cloud.script("GET", _TAGS, _gated_tags(arrived, gate))
        provider = _cloud_provider(cloud.origin)
        await _disconnect_during_probe(provider, ProviderCredentials(api_key=_KEY, api_base=local.origin), arrived, gate)

    assert provider.connected is False
    assert provider.cloud_available is False
    assert getattr(provider, "_cloud_client") is None


@pytest.mark.asyncio
async def test_chat_stream_sends_tools_without_a_tool_choice_when_none_is_given() -> None:
    """Offering tools with no tool choice sends the tool list and no ``tool_choice`` field.

    One-line change that fails it: change ``if tool_choice is not None:`` to ``if True:`` at ollama.py:1451.
    """
    frames = (
        json.dumps({"message": {"role": "assistant", "content": "ok"}, "done": False}).encode() + b"\n",
        json.dumps({"done": True}).encode() + b"\n",
    )
    with ScriptedHttpServer() as local:
        local.script("GET", _TAGS, json_response(200, {"models": [{"name": "seed"}]}))
        local.script("POST", _CHAT, ScriptedResponse(headers=(("content-type", "application/x-ndjson"),), chunks=frames))
        provider = OllamaProvider()
        await provider.connect(ProviderCredentials(api_base=local.origin))
        try:
            pieces = [piece async for piece in provider.chat_stream(_ask(), "llama3", tools=[_decompile_tool()])]
        finally:
            await provider.disconnect()
        body = local.requests(_CHAT)[0].json_object()

    assert pieces == ["ok"]
    assert set(body) == {"model", "messages", "stream", "options", "tools"}
    assert [tool["function"]["name"] for tool in body["tools"]] == ["ghidra__decompile"]
