# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Startup gates for user-defined provider instances.

These gates run the production startup path -- ``_load_provider_connect_policy``
and ``_initialize_providers`` from :mod:`intellicrack.main` -- against a
redirected per-user state root holding real ``.env`` and ``providers.json``
files and a loopback OpenAI-compatible endpoint. They fail when:

* an instance created from a keyless preset (vLLM, LM Studio, LiteLLM) is not
  connected at startup because it has no API key;
* an instance whose own record is disabled is connected anyway;
* startup loads an instance whose ``.env`` variables collide with another
  instance's or a built-in's, which the creation rule refuses.
"""

from __future__ import annotations

import importlib
import json
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.core.config import Config, get_config_file
from intellicrack.core.logging import get_logger
from intellicrack.credentials.env_loader import CredentialLoader, unregister_instance_mapping
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import ProviderInstance, instance_from_preset_id
from intellicrack.providers.registry import ProviderRegistry
from tests._helpers.openai_models_server import OpenAIModelsServer
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator
    from pathlib import Path

    from structlog.stdlib import BoundLogger

    from intellicrack.credentials.provider_settings import ProviderConnectPolicy


_main_module = importlib.import_module("intellicrack.main")
_initialize_providers = cast(
    "Callable[[ProviderRegistry, CredentialLoader, BoundLogger, ProviderConnectPolicy | None], Coroutine[object, object, None]]",
    _main_module._initialize_providers,
)
_load_provider_connect_policy = cast(
    "Callable[[Config, CredentialLoader, BoundLogger], ProviderConnectPolicy]",
    _main_module._load_provider_connect_policy,
)
_resolve_env_path = cast("Callable[[], Path]", _main_module._resolve_env_path)

_OFFLINE_SECTIONS: dict[str, dict[str, object]] = {
    "ollama": {"enabled": False, "schema_version": 3},
    "local_transformers": {"enabled": False, "schema_version": 3},
}
_MODEL_ID = "served-model"
_INSTANCE_IDS: tuple[str, ...] = ("local-vllm", "my-gw", "my_gw", "xai")


@pytest.fixture
def state_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Redirect the per-user state root into the test directory with no provider variables set.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Path: The redirected state root.
    """
    isolate_provider_environment(monkeypatch)
    for name in ("LOCAL_VLLM_API_KEY", "MY_GW_API_KEY", "LOCAL_VLLM_API_BASE", "MY_GW_API_BASE"):
        monkeypatch.delenv(name, raising=False)
    with redirected_state_root(monkeypatch, tmp_path) as root:
        yield root
    for instance_id in _INSTANCE_IDS:
        unregister_instance_mapping(instance_id)


@pytest.fixture
def keyless_endpoint() -> Iterator[OpenAIModelsServer]:
    """Provide a loopback OpenAI-compatible endpoint that accepts requests without a key.

    Yields:
        OpenAIModelsServer: The running server.
    """
    with OpenAIModelsServer(model_ids=[_MODEL_ID]) as server:
        yield server


def _write_state(env_content: str, instances: dict[str, ProviderInstance], sections: dict[str, dict[str, object]] | None = None) -> None:
    """Write the ``.env`` and ``providers.json`` files startup reads.

    Args:
        env_content: ``.env`` file content.
        instances: Instance records to store, keyed by the id they are stored under.
        sections: Extra provider sections.
    """
    _ = _resolve_env_path().write_text(env_content, encoding="utf-8")
    settings_path = get_config_file("providers.json")
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {**_OFFLINE_SECTIONS, **(sections or {})}
    payload["instances"] = {
        instance_id: instance.to_mapping() | {"instance_id": instance_id} for instance_id, instance in instances.items()
    }
    _ = settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


async def _run_startup() -> ProviderRegistry:
    """Run the production provider startup sequence.

    Returns:
        ProviderRegistry: The populated registry.
    """
    logger: BoundLogger = get_logger(__name__)
    credentials = CredentialLoader(_resolve_env_path())
    registry = ProviderRegistry()
    policy = _load_provider_connect_policy(Config(), credentials, logger)
    await _initialize_providers(registry, credentials, logger, policy)
    return registry


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_keyless_preset_instance_connects_at_startup(keyless_endpoint: OpenAIModelsServer) -> None:
    """A vLLM-preset instance with no key connects at launch and lists its models without a key.

    Args:
        keyless_endpoint: Keyless loopback endpoint fixture.
    """
    instance = instance_from_preset_id("vllm", instance_id="local-vllm")
    assert instance is not None
    instance.api_base = keyless_endpoint.base_url
    _write_state("", {"local-vllm": instance})

    registry = await _run_startup()

    provider = registry.get("local-vllm")
    assert isinstance(provider, ConfigurableProvider)
    assert provider.is_connected, "a keyless preset instance was left unconnected at startup"
    models = await provider.list_models()
    assert [model.id for model in models] == [_MODEL_ID]
    assert "authorization" not in keyless_endpoint.requests()[-1].headers
    await provider.disconnect()


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_disabled_instance_is_not_connected_at_startup(keyless_endpoint: OpenAIModelsServer) -> None:
    """An instance whose record is disabled stays registered but unconnected.

    Args:
        keyless_endpoint: Keyless loopback endpoint fixture.
    """
    instance = ProviderInstance(
        instance_id="my-gw",
        api_base=keyless_endpoint.base_url,
        requires_api_key=False,
        enabled=False,
    )
    _write_state("MY_GW_API_KEY=sk-gw-disabled\n", {"my-gw": instance})

    registry = await _run_startup()

    provider = registry.get("my-gw")
    assert provider is not None
    assert provider.is_connected is False


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_startup_skips_instances_whose_variables_collide(keyless_endpoint: OpenAIModelsServer) -> None:
    """Startup loads only the instance that owns ``MY_GW_*`` and none that reads a built-in's variable.

    Args:
        keyless_endpoint: Keyless loopback endpoint fixture.
    """
    records = {
        instance_id: ProviderInstance(instance_id=instance_id, api_base=keyless_endpoint.base_url, requires_api_key=False)
        for instance_id in ("my-gw", "my_gw", "xai")
    }
    _write_state("", records)

    registry = await _run_startup()

    assert registry.get("my-gw") is not None
    assert registry.get("my_gw") is None
    assert registry.get("xai") is None
    my_gw = registry.get("my-gw")
    assert my_gw is not None
    assert my_gw.is_connected
    await my_gw.disconnect()
