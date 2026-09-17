# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Startup gates: saved provider settings decide how providers connect at launch.

These gates run the production startup path -- ``_resolve_env_path``,
``_load_provider_connect_policy`` and ``_initialize_providers`` -- against a
redirected per-user state root holding real ``.env`` and ``providers.json``
files, a real :class:`ProviderRegistry`, the real provider classes, and a
loopback server that accepts only one API key. They fail when:

* an OpenAI-compatible gateway saved in Provider Settings (base URL,
  organization, timeout) is ignored at startup, so the key is sent to
  ``api.openai.com`` and rejected;
* a provider whose startup connect is rejected is dropped from the registry
  instead of staying registered for a reconnect from Provider Settings;
* a provider whose construction failed cannot be constructed on demand;
* a provider disabled in ``providers.json`` or the application configuration is
  still connected;
* OpenRouter's saved base URL or a keyless Ollama host is ignored.
"""

from __future__ import annotations

import importlib
import json
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.core.config import Config, ProviderConfig, get_config_file
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.registry import ProviderRegistry
from tests._helpers.provider_endpoint_server import OLLAMA_TAGS_PATH, OPENAI_COMPATIBLE_MODELS_PATH, ProviderEndpointServer
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

_GATEWAY_KEY = "venice-" + ("v" * 40)
_OFFLINE_SECTIONS: dict[str, dict[str, object]] = {
    "ollama": {"enabled": False, "schema_version": 2},
    "local_transformers": {"enabled": False, "schema_version": 2},
}


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
    with redirected_state_root(monkeypatch, tmp_path) as root:
        yield root


@pytest.fixture
def gateway() -> Iterator[ProviderEndpointServer]:
    """Provide a loopback OpenAI-compatible gateway accepting only the gateway key.

    Yields:
        ProviderEndpointServer: The running server.
    """
    with ProviderEndpointServer(accepted_key=_GATEWAY_KEY, model_ids=["venice-uncensored", "llama-3.3-70b"]) as server:
        yield server


def _write_state(env_content: str, sections: dict[str, dict[str, object]]) -> None:
    """Write the ``.env`` and ``providers.json`` files startup reads.

    Args:
        env_content: ``.env`` file content.
        sections: ``providers.json`` provider sections.
    """
    _ = _resolve_env_path().write_text(env_content, encoding="utf-8")
    settings_path = get_config_file("providers.json")
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    _ = settings_path.write_text(json.dumps(sections, indent=2), encoding="utf-8")


async def _run_startup(config: Config | None = None) -> ProviderRegistry:
    """Run the production provider startup sequence.

    Args:
        config: Application configuration; defaults to a fresh ``Config``.

    Returns:
        ProviderRegistry: The populated registry.
    """
    logger: BoundLogger = get_logger(__name__)
    credentials = CredentialLoader(_resolve_env_path())
    registry = ProviderRegistry()
    policy = _load_provider_connect_policy(config if config is not None else Config(), credentials, logger)
    await _initialize_providers(registry, credentials, logger, policy)
    return registry


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_startup_connects_openai_through_gateway_saved_in_provider_settings(gateway: ProviderEndpointServer) -> None:
    """The base URL, organization and timeout saved by Provider Settings are used at launch.

    ``providers.json`` holds the gateway settings exactly as earlier releases
    saved them; ``.env`` holds only the gateway's key.

    Args:
        gateway: Loopback gateway fixture.
    """
    _write_state(
        f"OPENAI_API_KEY={_GATEWAY_KEY}\n",
        {
            "openai": {
                "enabled": True,
                "api_base": gateway.openai_compatible_base_url,
                "organization_id": "org-venice",
                "timeout_seconds": 90,
                "default_model": "venice-uncensored",
            },
            **_OFFLINE_SECTIONS,
        },
    )

    registry = await _run_startup()

    openai = registry.get(provider_ids.OPENAI)
    assert openai is not None
    assert openai.is_connected
    probes = gateway.requests(OPENAI_COMPATIBLE_MODELS_PATH)
    assert probes, "startup never contacted the saved gateway"
    assert probes[-1].headers["authorization"] == f"Bearer {_GATEWAY_KEY}"
    assert probes[-1].headers["openai-organization"] == "org-venice"
    assert probes[-1].headers["x-stainless-read-timeout"] == "90.0"
    await openai.disconnect()

    next_launch = CredentialLoader(_resolve_env_path()).get_credentials(provider_ids.OPENAI)
    assert next_launch is not None
    assert next_launch.api_base == gateway.openai_compatible_base_url
    assert next_launch.organization_id == "org-venice"


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_rejected_provider_stays_registered_and_reconnects(gateway: ProviderEndpointServer) -> None:
    """A provider whose startup connect is rejected can be reconnected on the same instance.

    Args:
        gateway: Loopback gateway fixture.
    """
    _write_state(
        f"OPENAI_API_KEY=sk-{'w' * 48}\nOPENAI_API_BASE={gateway.openai_compatible_base_url}\n",
        _OFFLINE_SECTIONS,
    )

    registry = await _run_startup()

    rejected = registry.get(provider_ids.OPENAI)
    assert rejected is not None, "a provider rejected at startup must stay registered"
    assert not rejected.is_connected
    assert len(gateway.requests(OPENAI_COMPATIBLE_MODELS_PATH)) == 1

    assert await registry.connect_provider(
        provider_ids.OPENAI,
        ProviderCredentials(api_key=_GATEWAY_KEY, api_base=gateway.openai_compatible_base_url),
    )
    assert registry.get(provider_ids.OPENAI) is rejected
    assert rejected.is_connected
    await rejected.disconnect()


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_provider_whose_construction_failed_is_constructed_on_reconnect(
    gateway: ProviderEndpointServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A construction failure at startup leaves the class registered for on-demand construction.

    The first ``OpenAIProvider`` construction raises, as a broken SDK import
    or client setup would; later constructions succeed.

    Args:
        gateway: Loopback gateway fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    real_init = OpenAIProvider.__init__
    constructions: list[int] = []

    def _fail_first_construction(self: OpenAIProvider) -> None:
        constructions.append(len(constructions))
        if len(constructions) == 1:
            failure = "OpenAI SDK client setup failed during startup"
            raise RuntimeError(failure)
        real_init(self)

    monkeypatch.setattr(OpenAIProvider, "__init__", _fail_first_construction)
    _write_state(f"OPENAI_API_KEY={_GATEWAY_KEY}\nOPENAI_API_BASE={gateway.openai_compatible_base_url}\n", _OFFLINE_SECTIONS)

    registry = await _run_startup()

    assert registry.get(provider_ids.OPENAI) is None
    assert await registry.connect_provider(
        provider_ids.OPENAI,
        ProviderCredentials(api_key=_GATEWAY_KEY, api_base=gateway.openai_compatible_base_url),
    )
    constructed = registry.get(provider_ids.OPENAI)
    assert isinstance(constructed, OpenAIProvider)
    assert constructed.is_connected
    await constructed.disconnect()


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
@pytest.mark.parametrize("disabled_in", ["providers_json", "application_config"])
async def test_disabled_provider_is_registered_but_never_contacted(gateway: ProviderEndpointServer, disabled_in: str) -> None:
    """A provider disabled in either settings store is registered without connecting.

    Args:
        gateway: Loopback gateway fixture.
        disabled_in: Which store disables the provider.
    """
    sections = dict(_OFFLINE_SECTIONS)
    config = Config()
    if disabled_in == "providers_json":
        sections["openai"] = {"enabled": False, "schema_version": 2}
    else:
        config.providers[provider_ids.OPENAI] = ProviderConfig(enabled=False)
    _write_state(f"OPENAI_API_KEY={_GATEWAY_KEY}\nOPENAI_API_BASE={gateway.openai_compatible_base_url}\n", sections)

    registry = await _run_startup(config)

    disabled = registry.get(provider_ids.OPENAI)
    assert disabled is not None
    assert not disabled.is_connected
    assert gateway.requests(OPENAI_COMPATIBLE_MODELS_PATH) == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_startup_connects_openrouter_to_saved_base_url(gateway: ProviderEndpointServer) -> None:
    """OpenRouter connects to the base URL saved in ``OPENROUTER_API_BASE``.

    Args:
        gateway: Loopback gateway fixture.
    """
    _write_state(f"OPENROUTER_API_KEY={_GATEWAY_KEY}\nOPENROUTER_API_BASE={gateway.openai_compatible_base_url}\n", _OFFLINE_SECTIONS)

    registry = await _run_startup()

    openrouter = registry.get(provider_ids.OPENROUTER)
    assert openrouter is not None
    assert openrouter.is_connected
    assert gateway.requests(OPENAI_COMPATIBLE_MODELS_PATH)[-1].headers["authorization"] == f"Bearer {_GATEWAY_KEY}"
    await openrouter.disconnect()


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_startup_connects_keyless_ollama_to_saved_host(gateway: ProviderEndpointServer) -> None:
    """Ollama without an API key connects to the host saved in ``OLLAMA_HOST``.

    Args:
        gateway: Loopback gateway fixture.
    """
    _write_state(
        f"OLLAMA_HOST={gateway.ollama_base_url}\n",
        {"local_transformers": {"enabled": False, "schema_version": 2}},
    )

    registry = await _run_startup()

    ollama = registry.get(provider_ids.OLLAMA)
    assert ollama is not None
    assert ollama.is_connected
    assert gateway.requests(OLLAMA_TAGS_PATH), "Ollama never contacted the saved host"
    await ollama.disconnect()
