# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass critical-coverage tests for the XPU utilities, model loader, local transformers provider and Ollama provider.

Two groups of lines that the earlier passes could not reach are covered with real objects:

* The import-time fallbacks for ``torch``, ``transformers`` and ``bitsandbytes`` are run in a real child interpreter in which both packages
  are made unimportable with the import system's own switch (``sys.modules[name] = None``). The child imports the three product modules and
  reports the state the fallbacks leave and what each public entry point answers in that state.
* The two ``AuthenticationError`` branches of the Ollama connect probes that need the shared client to be gone already. Two probes run
  concurrently on one provider against a loopback server that holds each reply; the second probe replaces the shared client, its 401
  reaches its handler first and clears the client, and the first probe's 401 then reaches its handler with no client left.
"""

from __future__ import annotations

import asyncio
import os
import threading
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
from structlog.testing import capture_logs

from intellicrack.core.types import ProviderCredentials, ProviderError
from intellicrack.providers.ollama import OllamaProvider
from tests._helpers.child_python import run_child_json
from tests._helpers.scripted_http_server import RecordedRequest, ScriptedHttpServer, ScriptedResponse, json_response


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    import httpx


pytestmark = pytest.mark.spawns_process

_CHILD_TIMEOUT_SECONDS: Final[float] = 300.0
_WAIT_SECONDS: Final[float] = 15.0
_TAGS: Final[str] = "/api/tags"
_KEY: Final[str] = "loopback-cloud-credential"

_BLOCKED_IMPORT_CHILD: Final[str] = """
import asyncio
import json
import sys

sys.modules["torch"] = None
sys.modules["transformers"] = None

from intellicrack.core.types import ProviderCredentials
from intellicrack.providers import local_transformers, model_loader, xpu_utils


def outcome(call):
    try:
        return {"value": call()}
    except BaseException as exc:
        return {"error_type": type(exc).__name__, "error_text": str(exc)}


provider = local_transformers.LocalTransformersProvider()
connect = outcome(lambda: asyncio.run(provider.connect(ProviderCredentials())))
config = model_loader.ModelConfig(model_id="fixture/model-that-is-never-fetched")

print(json.dumps({
    "xpu_torch_module_is_none": xpu_utils._torch_module is None,
    "xpu_is_available": xpu_utils.is_xpu_available(),
    "xpu_device_count": xpu_utils.get_xpu_device_count(),
    "xpu_device_info": xpu_utils.get_xpu_device_info(0),
    "xpu_is_arc_b580": xpu_utils.is_arc_b580(),
    "xpu_memory_info": list(xpu_utils.get_xpu_memory_info(0)),
    "xpu_optimal_dtype": xpu_utils.get_optimal_dtype_for_xpu(),
    "xpu_initialize": outcome(lambda: str(xpu_utils.initialize_xpu(0))),
    "lt_torch_is_none": local_transformers._torch is None,
    "lt_auto_model_is_none": local_transformers._AutoModelForCausalLM is None,
    "lt_auto_tokenizer_is_none": local_transformers._AutoTokenizer is None,
    "lt_connect": connect,
    "lt_connected": provider.connected,
    "lt_device_type": provider.device_type,
    "lt_cuda_available": provider.cuda_available,
    "lt_xpu_available": provider.xpu_available,
    "ml_torch_is_none": model_loader._torch is None,
    "ml_auto_model_is_none": model_loader.AutoModelForCausalLM is None,
    "ml_auto_tokenizer_is_none": model_loader.AutoTokenizer is None,
    "ml_bitsandbytes_config_is_none": model_loader.BitsAndBytesConfig is None,
    "ml_load_cpu": outcome(lambda: model_loader.load_model_for_cpu(config)),
    "ml_load_xpu": outcome(lambda: model_loader.load_model_for_xpu(config)),
}))
"""


@pytest.fixture(scope="module")
def blocked_state() -> dict[str, Any]:
    """Run the three product modules in a child where ``torch`` and ``transformers`` cannot be imported.

    Returns:
        dict[str, Any]: The JSON state the child printed.
    """
    coverage_env = {name: value for name, value in os.environ.items() if name.startswith("COV")}
    return run_child_json(_BLOCKED_IMPORT_CHILD, timeout_s=_CHILD_TIMEOUT_SECONDS, extra_env=coverage_env)


def test_xpu_utils_keeps_no_torch_handle_when_torch_cannot_be_imported(blocked_state: dict[str, Any]) -> None:
    """With ``torch`` unimportable the module still imports and its torch handle is ``None``.

    Probe key: ``blocked_torch_transformers`` (``import_xpu_utils.torch_module_is_none`` is true).

    One-line change that fails it: replace ``_torch_module = None`` with ``_torch_module = object()`` at xpu_utils.py:32.

    Args:
        blocked_state: State reported by the child interpreter.
    """
    assert blocked_state["xpu_torch_module_is_none"] is True


def test_xpu_utils_reports_no_device_without_torch(blocked_state: dict[str, Any]) -> None:
    """Without ``torch`` every XPU probe answers its neutral value instead of raising.

    Probe key: ``blocked_torch_transformers`` (``xpu_utils_calls``).

    One-line change that fails it: change ``return False`` to ``return True`` in the ``torch is None`` branch of ``is_xpu_available`` at
    xpu_utils.py:96.

    Args:
        blocked_state: State reported by the child interpreter.
    """
    assert blocked_state["xpu_is_available"] is False
    assert blocked_state["xpu_device_count"] == 0
    assert blocked_state["xpu_device_info"] is None
    assert blocked_state["xpu_is_arc_b580"] is False
    assert blocked_state["xpu_memory_info"] == [0, 0]
    assert blocked_state["xpu_optimal_dtype"] == "float32"


def test_xpu_initialization_names_the_missing_torch(blocked_state: dict[str, Any]) -> None:
    """Initializing the XPU without ``torch`` raises a ``RuntimeError`` that says PyTorch is not installed.

    Probe key: ``blocked_torch_transformers`` (``xpu_utils_calls.initialize_xpu_0``).

    One-line change that fails it: change ``raise RuntimeError(_ERR_PYTORCH_NOT_INSTALLED)`` to ``raise ValueError(_ERR_PYTORCH_NOT_INSTALLED)``
    at xpu_utils.py:493.

    Args:
        blocked_state: State reported by the child interpreter.
    """
    failure = blocked_state["xpu_initialize"]
    assert failure["error_type"] == "RuntimeError"
    assert "PyTorch is not installed" in failure["error_text"]


def test_local_transformers_keeps_no_torch_or_transformers_handles(blocked_state: dict[str, Any]) -> None:
    """With both packages unimportable the provider module imports and all three handles are ``None``.

    Probe key: ``blocked_torch_transformers`` (``import_local_transformers``).

    One-line change that fails it: replace ``_AutoTokenizer = None`` with ``_AutoTokenizer = object()`` at local_transformers.py:84.

    Args:
        blocked_state: State reported by the child interpreter.
    """
    assert blocked_state["lt_torch_is_none"] is True
    assert blocked_state["lt_auto_model_is_none"] is True
    assert blocked_state["lt_auto_tokenizer_is_none"] is True


def test_local_transformers_connect_refuses_without_torch(blocked_state: dict[str, Any]) -> None:
    """Connecting without ``torch`` raises a ``ProviderError`` that names torch and leaves the provider disconnected on the CPU.

    Probe key: ``blocked_torch_transformers`` (``local_transformers_calls.connect``).

    One-line change that fails it: change ``if _torch is None:`` to ``if False:`` at local_transformers.py:341.

    Args:
        blocked_state: State reported by the child interpreter.
    """
    failure = blocked_state["lt_connect"]
    assert failure["error_type"] == "ProviderError"
    assert "torch is required" in failure["error_text"]
    assert blocked_state["lt_connected"] is False
    assert blocked_state["lt_device_type"] == "cpu"
    assert blocked_state["lt_cuda_available"] is False
    assert blocked_state["lt_xpu_available"] is False


def test_model_loader_keeps_no_torch_transformers_or_quantization_handles(blocked_state: dict[str, Any]) -> None:
    """With both packages unimportable the loader module imports and all four handles are ``None``.

    Probe key: ``blocked_torch_transformers`` (``import_model_loader``).

    One-line change that fails it: replace ``BitsAndBytesConfig = None`` with ``BitsAndBytesConfig = object()`` at model_loader.py:44.

    Args:
        blocked_state: State reported by the child interpreter.
    """
    assert blocked_state["ml_torch_is_none"] is True
    assert blocked_state["ml_auto_model_is_none"] is True
    assert blocked_state["ml_auto_tokenizer_is_none"] is True
    assert blocked_state["ml_bitsandbytes_config_is_none"] is True


def test_model_loader_entry_points_raise_import_error_without_dependencies(blocked_state: dict[str, Any]) -> None:
    """Loading a model for the CPU or the XPU without the dependencies raises an ``ImportError`` naming torch and transformers.

    Probe key: ``blocked_torch_transformers`` (``model_loader_calls.load_model_for_cpu`` and ``load_model_for_xpu``).

    One-line change that fails it: change ``raise ImportError(_ERR_MISSING_DEPS)`` to ``raise RuntimeError(_ERR_MISSING_DEPS)`` at
    model_loader.py:763.

    Args:
        blocked_state: State reported by the child interpreter.
    """
    for key in ("ml_load_cpu", "ml_load_xpu"):
        failure = blocked_state[key]
        assert failure["error_type"] == "ImportError"
        assert "transformers" in failure["error_text"]
        assert "torch" in failure["error_text"]


def _held_unauthorized(arrived: threading.Event, gate: threading.Event) -> Callable[[RecordedRequest], ScriptedResponse]:
    """Build a handler that announces a request and answers 401 only after a gate opens.

    Args:
        arrived: Set as soon as the request reaches the server.
        gate: The response body is written only after this event is set.

    Returns:
        Callable[[RecordedRequest], ScriptedResponse]: The handler.
    """

    def _reply(request: RecordedRequest) -> ScriptedResponse:
        """Answer one probe.

        Args:
            request: The received request.

        Returns:
            ScriptedResponse: A 401 whose body is gated on ``gate``.
        """
        del request
        arrived.set()
        return ScriptedResponse(status=401, chunks=(b'{"error": "unauthorized"}',), gates={0: gate})

    return _reply


def _events(captured: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Filter captured structured-log entries by event name.

    Args:
        captured: Entries collected by ``structlog.testing.capture_logs``.
        name: Event name to keep.

    Returns:
        list[Mapping[str, object]]: The entries logged under that event.
    """
    return [entry for entry in captured if entry.get("event") == name]


async def _release_second_probe_first(
    provider: OllamaProvider,
    credentials: ProviderCredentials,
    client_attr: str,
    arrived: tuple[threading.Event, threading.Event],
    gates: tuple[threading.Event, threading.Event],
) -> None:
    """Run two probes concurrently and answer the second one before the first.

    The second probe replaces the shared client while the first is held. Its 401 therefore reaches the provider first, closes that client and
    clears it, and the first probe's 401 later reaches its handler with no client left.

    Args:
        provider: The provider to connect twice.
        credentials: Credentials for both connects.
        client_attr: Name of the shared client attribute (``_local_client`` or ``_cloud_client``).
        arrived: Events set when the first and the second request reach the server.
        gates: Events that release the first and the second response.
    """
    first = asyncio.create_task(provider.connect(credentials))
    second: asyncio.Task[None] | None = None
    first_client: httpx.AsyncClient | None = None
    try:
        assert await asyncio.to_thread(arrived[0].wait, _WAIT_SECONDS)
        first_client = cast("httpx.AsyncClient | None", getattr(provider, client_attr))
        second = asyncio.create_task(provider.connect(credentials))
        assert await asyncio.to_thread(arrived[1].wait, _WAIT_SECONDS)
        assert getattr(provider, client_attr) is not first_client
        gates[1].set()
        with pytest.raises(ProviderError):
            await asyncio.wait_for(second, _WAIT_SECONDS)
        assert getattr(provider, client_attr) is None
        assert not first.done()
        gates[0].set()
        with pytest.raises(ProviderError):
            await asyncio.wait_for(first, _WAIT_SECONDS)
    finally:
        gates[0].set()
        gates[1].set()
        pending = [task for task in (first, second) if task is not None]
        _ = await asyncio.gather(*pending, return_exceptions=True)
        if first_client is not None:
            await first_client.aclose()


@pytest.mark.asyncio
async def test_local_probe_unauthorized_after_the_shared_client_was_cleared() -> None:
    """A local probe whose 401 arrives after another probe cleared the shared client finishes without touching the client.

    Probe key: ``ollama_two_concurrent_401_local`` (the traced frames show one handler run ending at ``if self._local_client:`` and the other
    continuing to ``aclose``).

    One-line change that fails it: remove the ``if self._local_client:`` guard at ollama.py:329, which then calls ``aclose`` on ``None`` and
    lets an ``AttributeError`` escape the connect instead of the ``ProviderError``.
    """
    arrived = (threading.Event(), threading.Event())
    gates = (threading.Event(), threading.Event())
    with capture_logs() as captured, ScriptedHttpServer() as local:
        local.script(
            "GET",
            _TAGS,
            _held_unauthorized(arrived[0], gates[0]),
            _held_unauthorized(arrived[1], gates[1]),
        )
        provider = OllamaProvider()
        await _release_second_probe_first(provider, ProviderCredentials(api_base=local.origin), "_local_client", arrived, gates)

    assert len(_events(captured, "local_ollama_auth_failed")) == 2
    assert _events(captured, "local_ollama_unavailable") == []
    assert provider.connected is False
    assert provider.local_available is False
    assert getattr(provider, "_local_client") is None


@pytest.mark.asyncio
async def test_cloud_probe_unauthorized_after_the_shared_client_was_cleared() -> None:
    """A cloud probe whose 401 arrives after another probe cleared the shared client finishes without touching the client.

    Probe key: ``ollama_two_concurrent_401_cloud`` (the traced frames show one handler run ending at ``if self._cloud_client:`` and the other
    continuing to ``aclose``).

    One-line change that fails it: remove the ``if self._cloud_client:`` guard at ollama.py:355, which then calls ``aclose`` on ``None`` and
    lets an ``AttributeError`` escape the connect instead of the ``ProviderError``.
    """
    arrived = (threading.Event(), threading.Event())
    gates = (threading.Event(), threading.Event())
    with capture_logs() as captured, ScriptedHttpServer() as local, ScriptedHttpServer() as cloud:
        local.script(
            "GET",
            _TAGS,
            json_response(500, {"error": "daemon down"}),
            json_response(500, {"error": "daemon down"}),
        )
        cloud.script(
            "GET",
            _TAGS,
            _held_unauthorized(arrived[0], gates[0]),
            _held_unauthorized(arrived[1], gates[1]),
        )
        cloud_url = cloud.origin

        class _LoopbackCloudOllama(OllamaProvider):
            """OllamaProvider whose cloud endpoint is a loopback server."""

            CLOUD_API_URL = cloud_url

        provider = _LoopbackCloudOllama()
        await _release_second_probe_first(
            provider,
            ProviderCredentials(api_key=_KEY, api_base=local.origin),
            "_cloud_client",
            arrived,
            gates,
        )

    assert len(_events(captured, "cloud_api_key_invalid")) == 2
    assert _events(captured, "cloud_ollama_unavailable") == []
    assert provider.connected is False
    assert provider.cloud_available is False
    assert getattr(provider, "_cloud_client") is None
