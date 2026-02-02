"""Integration tests that display dynamically fetched models from each provider.

These tests fetch and DISPLAY the actual models available from each provider's API.
Run with pytest -v -s to see the model output.
"""

from __future__ import annotations

import pytest

from intellicrack.core.types import ProviderName
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


@pytest.mark.integration
class TestModelDiscoveryDisplay:
    """Tests that fetch and display available models from each provider."""

    @pytest.mark.asyncio
    async def test_display_openai_models(
        self,
        openai_provider: OpenAIProvider,
    ) -> None:
        """Fetch and display all available OpenAI models."""
        models = await openai_provider.list_models()

        print("\n" + "=" * 60)
        print(f"OPENAI MODELS ({len(models)} total)")
        print("=" * 60)
        for model in sorted(models, key=lambda m: m.id):
            tools = "tools" if model.supports_tools else ""
            vision = "vision" if model.supports_vision else ""
            caps = ", ".join(filter(None, [tools, vision])) or "base"
            print(f"  {model.id:<45} [{caps}]")
        print("=" * 60)

        assert len(models) > 0, "OpenAI should return models"

    @pytest.mark.asyncio
    async def test_display_google_models(
        self,
        google_provider: GoogleProvider,
    ) -> None:
        """Fetch and display all available Google Gemini models."""
        models = await google_provider.list_models()

        print("\n" + "=" * 60)
        print(f"GOOGLE GEMINI MODELS ({len(models)} total)")
        print("=" * 60)
        for model in sorted(models, key=lambda m: m.id):
            tools = "tools" if model.supports_tools else ""
            vision = "vision" if model.supports_vision else ""
            caps = ", ".join(filter(None, [tools, vision])) or "base"
            ctx = f"{model.context_window:,}" if model.context_window else "?"
            print(f"  {model.id:<45} [ctx:{ctx}, {caps}]")
        print("=" * 60)

        assert len(models) > 0, "Google should return models"

    @pytest.mark.asyncio
    async def test_display_openrouter_models(
        self,
        openrouter_provider: OpenRouterProvider,
    ) -> None:
        """Fetch and display all available OpenRouter models."""
        models = await openrouter_provider.list_models()

        print("\n" + "=" * 60)
        print(f"OPENROUTER MODELS ({len(models)} total)")
        print("=" * 60)

        by_provider: dict[str, list[str]] = {}
        for model in models:
            provider_prefix = model.id.split("/")[0] if "/" in model.id else "other"
            if provider_prefix not in by_provider:
                by_provider[provider_prefix] = []
            by_provider[provider_prefix].append(model.id)

        for provider_prefix in sorted(by_provider.keys()):
            model_ids = by_provider[provider_prefix]
            print(f"\n  [{provider_prefix}] ({len(model_ids)} models)")
            for model_id in sorted(model_ids)[:10]:
                print(f"    {model_id}")
            if len(model_ids) > 10:
                print(f"    ... and {len(model_ids) - 10} more")

        print("\n" + "=" * 60)

        assert len(models) > 0, "OpenRouter should return models"

    @pytest.mark.asyncio
    async def test_display_anthropic_models(
        self,
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """Fetch and display all available Anthropic Claude models."""
        models = await anthropic_provider.list_models()

        print("\n" + "=" * 60)
        print(f"ANTHROPIC CLAUDE MODELS ({len(models)} total)")
        print("=" * 60)
        for model in sorted(models, key=lambda m: m.id):
            tools = "tools" if model.supports_tools else ""
            vision = "vision" if model.supports_vision else ""
            caps = ", ".join(filter(None, [tools, vision])) or "base"
            print(f"  {model.id:<45} [{caps}]")
        print("=" * 60)

        assert len(models) > 0, "Anthropic should return models"

    @pytest.mark.asyncio
    async def test_display_ollama_models(
        self,
        ollama_provider: OllamaProvider,
    ) -> None:
        """Fetch and display all locally installed Ollama models."""
        models = await ollama_provider.list_models()

        print("\n" + "=" * 60)
        print(f"OLLAMA LOCAL MODELS ({len(models)} total)")
        print("=" * 60)
        if models:
            for model in sorted(models, key=lambda m: m.id):
                tools = "tools" if model.supports_tools else ""
                vision = "vision" if model.supports_vision else ""
                caps = ", ".join(filter(None, [tools, vision])) or "base"
                print(f"  {model.id:<45} [{caps}]")
        else:
            print("  (No models installed locally)")
        print("=" * 60)


@pytest.mark.integration
class TestAllProvidersModelCount:
    """Summary test showing model counts across all configured providers."""

    @pytest.mark.asyncio
    async def test_summary_all_providers(
        self,
        credential_loader,
        has_openai_key: bool,
        has_google_key: bool,
        has_openrouter_key: bool,
        has_anthropic_key: bool,
        has_ollama_available: bool,
    ) -> None:
        """Display summary of models available from all configured providers."""
        print("\n" + "=" * 60)
        print("PROVIDER MODEL AVAILABILITY SUMMARY")
        print("=" * 60)

        results: dict[str, int | str] = {}

        if has_openai_key:
            provider = OpenAIProvider()
            creds = credential_loader.get_credentials(ProviderName.OPENAI)
            await provider.connect(creds)
            models = await provider.list_models()
            results["OpenAI"] = len(models)
            await provider.disconnect()
        else:
            results["OpenAI"] = "NOT CONFIGURED"

        if has_google_key:
            provider = GoogleProvider()
            creds = credential_loader.get_credentials(ProviderName.GOOGLE)
            await provider.connect(creds)
            models = await provider.list_models()
            results["Google"] = len(models)
            await provider.disconnect()
        else:
            results["Google"] = "NOT CONFIGURED"

        if has_openrouter_key:
            provider = OpenRouterProvider()
            creds = credential_loader.get_credentials(ProviderName.OPENROUTER)
            await provider.connect(creds)
            models = await provider.list_models()
            results["OpenRouter"] = len(models)
            await provider.disconnect()
        else:
            results["OpenRouter"] = "NOT CONFIGURED"

        if has_anthropic_key:
            provider = AnthropicProvider()
            creds = credential_loader.get_credentials(ProviderName.ANTHROPIC)
            await provider.connect(creds)
            models = await provider.list_models()
            results["Anthropic"] = len(models)
            await provider.disconnect()
        else:
            results["Anthropic"] = "NOT CONFIGURED"

        if has_ollama_available:
            provider = OllamaProvider()
            creds = credential_loader.get_credentials(ProviderName.OLLAMA)
            if creds is None:
                from intellicrack.core.types import ProviderCredentials

                creds = ProviderCredentials(api_base="http://localhost:11434")
            await provider.connect(creds)
            models = await provider.list_models()
            results["Ollama"] = len(models)
            await provider.disconnect()
        else:
            results["Ollama"] = "NOT RUNNING"

        for provider_name, count in results.items():
            if isinstance(count, int):
                print(f"  {provider_name:<15} {count:>5} models")
            else:
                print(f"  {provider_name:<15} {count}")

        print("=" * 60)

        configured_count = sum(isinstance(v, int) for v in results.values())
        assert configured_count > 0, "At least one provider should be configured"
