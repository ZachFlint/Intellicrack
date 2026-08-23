# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for providers.registry module - provider registration and management."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, cast, override

import pytest

from intellicrack import providers as providers_pkg
from intellicrack.core.types import (
    AuthenticationError,
    ConfigurationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ToolCall,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import (
    CredentialLoaderProtocol,
    ProviderRegistry,
    get_provider_registry,
    reset_provider_registry,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from intellicrack.core.types import ThinkingConfig, ToolChoice, ToolDefinition


class ConcreteTestProvider(LLMProviderBase):
    """Minimal concrete provider for registry testing."""

    def __init__(self, provider_name: ProviderName = ProviderName.ANTHROPIC) -> None:
        """Initialize the test provider with the given name.

        Args:
            provider_name: The provider name to use.
        """
        super().__init__()
        self._name = provider_name

    @property
    @override
    def name(self) -> ProviderName:
        """The provider name.

        Returns:
            ProviderName: Configured ProviderName.
        """
        return self._name

    def mark_connected(self) -> None:
        """Set provider to connected state for testing."""
        self.connected = True

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark provider as connected.

        Args:
            credentials: Provider credentials.
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return empty model list.

        Returns:
            list[ModelInfo]: Empty list.
        """
        return []

    @override
    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Return empty response.

        Args:
            messages: Conversation history.
            model: Model ID.
            tools: Available tools.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool-selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable provider-side prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of empty message and None.
        """
        return Message(role="assistant", content="test"), None

    @override
    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Yield empty stream.

        Args:
            messages: Conversation history.
            model: Model ID.
            tools: Available tools.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool-selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable provider-side prompt caching.

        Yields:
            str: Empty string.
        """
        yield ""

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Return empty tool list.

        Args:
            tools: Tool definitions.

        Returns:
            list[dict[str, object]]: Empty list.
        """
        return []

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Return empty message list.

        Args:
            messages: Messages to convert.

        Returns:
            list[dict[str, object]]: Empty list.
        """
        return []


def _make_provider(
    name: ProviderName = ProviderName.ANTHROPIC,
) -> ConcreteTestProvider:
    """Create a test provider instance.

    Args:
        name: Provider name.

    Returns:
        ConcreteTestProvider: ConcreteTestProvider instance.
    """
    return ConcreteTestProvider(provider_name=name)


def _make_connected(
    name: ProviderName = ProviderName.ANTHROPIC,
) -> ConcreteTestProvider:
    """Create a connected test provider.

    Args:
        name: Provider name.

    Returns:
        ConcreteTestProvider: Connected ConcreteTestProvider.
    """
    p = ConcreteTestProvider(provider_name=name)
    p.mark_connected()
    return p


def test_registry_empty() -> None:
    """Verify empty registry has no providers."""
    reg = ProviderRegistry()
    assert reg.list_registered() == []
    assert reg.list_connected() == []
    assert reg.active is None
    assert reg.active_name is None


def test_register_provider() -> None:
    """Verify provider registration."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    assert ProviderName.ANTHROPIC in reg.list_registered()


def test_register_replaces_existing() -> None:
    """Verify re-registering replaces the provider."""
    reg = ProviderRegistry()
    p1 = _make_provider()
    p2 = _make_provider()
    reg.register(p1)
    reg.register(p2)
    assert reg.get(ProviderName.ANTHROPIC) is p2


def test_unregister_provider() -> None:
    """Verify provider unregistration."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    assert reg.unregister(ProviderName.ANTHROPIC) is True
    assert reg.list_registered() == []


def test_unregister_nonexistent() -> None:
    """Verify unregistering non-existent provider returns False."""
    reg = ProviderRegistry()
    assert reg.unregister(ProviderName.ANTHROPIC) is False


def test_unregister_clears_active() -> None:
    """Verify unregistering active provider clears active."""
    reg = ProviderRegistry()
    reg.register(_make_connected())
    reg.set_active(ProviderName.ANTHROPIC)
    reg.unregister(ProviderName.ANTHROPIC)
    assert reg.active_name is None


def test_get_registered() -> None:
    """Verify get returns registered provider."""
    reg = ProviderRegistry()
    provider = _make_provider()
    reg.register(provider)
    assert reg.get(ProviderName.ANTHROPIC) is provider


def test_get_not_registered() -> None:
    """Verify get returns None for unregistered provider."""
    reg = ProviderRegistry()
    assert reg.get(ProviderName.ANTHROPIC) is None


def test_get_or_raise_success() -> None:
    """Verify get_or_raise returns registered provider."""
    reg = ProviderRegistry()
    provider = _make_provider()
    reg.register(provider)
    assert reg.get_or_raise(ProviderName.ANTHROPIC) is provider


def test_get_or_raise_not_registered() -> None:
    """Verify get_or_raise raises ProviderError for unregistered."""
    reg = ProviderRegistry()
    with pytest.raises(ProviderError):
        reg.get_or_raise(ProviderName.ANTHROPIC)


def test_list_connected_empty() -> None:
    """Verify list_connected returns empty for disconnected providers."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    assert reg.list_connected() == []


def test_list_connected_with_connected() -> None:
    """Verify list_connected includes connected providers."""
    reg = ProviderRegistry()
    reg.register(_make_connected())
    assert ProviderName.ANTHROPIC in reg.list_connected()


def test_set_active_success() -> None:
    """Verify set_active works for connected provider."""
    reg = ProviderRegistry()
    provider = _make_connected()
    reg.register(provider)
    reg.set_active(ProviderName.ANTHROPIC)
    assert reg.active_name == ProviderName.ANTHROPIC
    assert reg.active is provider


def test_set_active_not_registered() -> None:
    """Verify set_active raises for unregistered provider."""
    reg = ProviderRegistry()
    with pytest.raises(ProviderError):
        reg.set_active(ProviderName.ANTHROPIC)


def test_set_active_not_connected() -> None:
    """Verify set_active raises for disconnected provider."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    with pytest.raises(ProviderError):
        reg.set_active(ProviderName.ANTHROPIC)


def test_has_connected_provider_false() -> None:
    """Verify has_connected_provider returns False when none connected."""
    reg = ProviderRegistry()
    reg.register(_make_provider())
    assert reg.has_connected_provider() is False


def test_has_connected_provider_true() -> None:
    """Verify has_connected_provider returns True when one connected."""
    reg = ProviderRegistry()
    reg.register(_make_connected())
    assert reg.has_connected_provider() is True


def test_multiple_providers() -> None:
    """Verify registry handles multiple providers."""
    reg = ProviderRegistry()
    reg.register(_make_provider(ProviderName.ANTHROPIC))
    reg.register(_make_provider(ProviderName.OPENAI))
    registered = reg.list_registered()
    assert ProviderName.ANTHROPIC in registered
    assert ProviderName.OPENAI in registered


def _reraise(err: BaseException) -> None:
    """Re-raise a previously captured exception.

    The exception passed in is propagated unchanged so that callers can
    plug arbitrary configured errors into the test providers.

    Args:
        err: The exception instance to re-raise.

    Raises:
        err: The exception instance supplied as the ``err`` argument.
    """
    raise err


class _ConnectFails(ConcreteTestProvider):
    """Provider whose connect() raises a configurable error."""

    def __init__(
        self,
        error: BaseException,
        provider_name: ProviderName = ProviderName.ANTHROPIC,
    ) -> None:
        """Initialize with the configured error and name.

        Args:
            error: The exception that ``connect()`` should raise.
            provider_name: The provider name to use.
        """
        super().__init__(provider_name=provider_name)
        self._error = error

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Raise the configured error when called.

        Args:
            credentials: Credentials passed by the caller (ignored).
        """
        _ = credentials
        _reraise(self._error)


class _DisconnectFails(ConcreteTestProvider):
    """Provider whose disconnect() raises a configurable error."""

    def __init__(
        self,
        error: BaseException,
        provider_name: ProviderName = ProviderName.ANTHROPIC,
    ) -> None:
        """Initialize with the configured error and name.

        Args:
            error: The exception that ``disconnect()`` should raise.
            provider_name: The provider name to use.
        """
        super().__init__(provider_name=provider_name)
        self.connected = True
        self._error = error
        self.disconnect_called = False

    @override
    async def disconnect(self) -> None:
        """Record the call and raise the configured error."""
        self.disconnect_called = True
        _reraise(self._error)


class _DisconnectTracksCalls(ConcreteTestProvider):
    """Provider that records whether disconnect() was invoked."""

    def __init__(
        self,
        provider_name: ProviderName = ProviderName.OPENAI,
    ) -> None:
        """Initialize with a provider name and prepare disconnect tracking.

        Args:
            provider_name: The provider name to use.
        """
        super().__init__(provider_name=provider_name)
        self.connected = True
        self.disconnect_called = False

    @override
    async def disconnect(self) -> None:
        """Mark the provider disconnected and record the call."""
        self.disconnect_called = True
        self.connected = False


class _StaticCredentialLoader:
    """Credential loader returning a configured credential mapping."""

    def __init__(self, creds: dict[ProviderName, ProviderCredentials]) -> None:
        """Initialize the loader with a static credential mapping.

        Args:
            creds: Mapping of ProviderName to ProviderCredentials.
        """
        self._creds = creds
        self.calls: list[ProviderName] = []

    def get_credentials(self, provider: ProviderName) -> ProviderCredentials | None:
        """Return the configured credentials for ``provider``.

        Args:
            provider: The provider whose credentials are requested.

        Returns:
            ProviderCredentials | None: The credential for the provider, or
            None when no entry is configured.
        """
        self.calls.append(provider)
        return self._creds.get(provider)


class TestF0001ConnectExceptionTuple:
    """F-0001: connect_provider must catch ProviderError subclasses.

    Without the fix the handler only caught generic exceptions; provider
    implementations raising ProviderError/AuthenticationError bypassed it.
    """

    @pytest.mark.asyncio
    @staticmethod
    async def test_authentication_error_is_caught_and_re_raised() -> None:
        """AuthenticationError raised by connect must propagate to the caller."""
        reg = ProviderRegistry()
        provider = _ConnectFails(
            AuthenticationError("bad key", provider_name=ProviderName.ANTHROPIC.value),
        )
        reg.register(provider)
        creds = ProviderCredentials(api_key="x")
        with pytest.raises(AuthenticationError):
            await reg.connect_provider(ProviderName.ANTHROPIC, creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_provider_error_is_caught_and_re_raised() -> None:
        """ProviderError raised by connect must propagate to the caller."""
        reg = ProviderRegistry()
        provider = _ConnectFails(
            ProviderError("nope", provider_name=ProviderName.ANTHROPIC.value),
        )
        reg.register(provider)
        creds = ProviderCredentials(api_key="x")
        with pytest.raises(ProviderError):
            await reg.connect_provider(ProviderName.ANTHROPIC, creds)

    @pytest.mark.asyncio
    @staticmethod
    async def test_configuration_error_is_caught_and_re_raised() -> None:
        """ConfigurationError raised by connect must propagate to the caller."""
        reg = ProviderRegistry()
        provider = _ConnectFails(
            ConfigurationError("bad config"),
        )
        reg.register(provider)
        creds = ProviderCredentials(api_key="x")
        with pytest.raises(ConfigurationError):
            await reg.connect_provider(ProviderName.ANTHROPIC, creds)


class TestF0002ConnectReturnsExplicitTrue:
    """F-0002: connect_provider returns explicit True on success."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_successful_connect_returns_true() -> None:
        """Successful connect_provider should return the boolean ``True``."""
        reg = ProviderRegistry()
        provider = _make_provider()
        reg.register(provider)
        creds = ProviderCredentials(api_key="x")
        result = await reg.connect_provider(ProviderName.ANTHROPIC, creds)
        assert result is True


class TestF0003CredentialLoaderConsumed:
    """F-0003: ProviderRegistry consumes the configured credential loader."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_loader_called_when_credentials_omitted() -> None:
        """When credentials are omitted, the loader must be queried."""
        creds = ProviderCredentials(api_key="loaded")
        loader = _StaticCredentialLoader({ProviderName.ANTHROPIC: creds})
        reg = ProviderRegistry(credential_loader=loader)
        provider = _make_provider()
        reg.register(provider)
        assert await reg.connect_provider(ProviderName.ANTHROPIC) is True
        assert ProviderName.ANTHROPIC in loader.calls
        assert provider.is_connected

    @pytest.mark.asyncio
    @staticmethod
    async def test_loader_not_called_when_credentials_supplied() -> None:
        """Explicit credentials must be used even when a loader is present."""
        loader = _StaticCredentialLoader({})
        reg = ProviderRegistry(credential_loader=loader)
        reg.register(_make_provider())
        creds = ProviderCredentials(api_key="explicit")
        assert await reg.connect_provider(ProviderName.ANTHROPIC, creds) is True
        assert loader.calls == []

    @pytest.mark.asyncio
    @staticmethod
    async def test_loader_returning_none_raises_provider_error() -> None:
        """If both arguments and loader yield no credentials, raise ProviderError."""
        loader = _StaticCredentialLoader({})
        reg = ProviderRegistry(credential_loader=loader)
        reg.register(_make_provider())
        with pytest.raises(ProviderError):
            await reg.connect_provider(ProviderName.ANTHROPIC)


class TestF0004GetProviderRegistryExport:
    """F-0004: get_provider_registry is exported from providers package."""

    @staticmethod
    def test_get_provider_registry_imports_from_package() -> None:
        """Import path ``intellicrack.providers.get_provider_registry`` must work."""
        assert providers_pkg.get_provider_registry is get_provider_registry
        assert "get_provider_registry" in providers_pkg.__all__


class TestF0005NameToClassMapping:
    """F-0005: Registry can map a ProviderName to a class for construction."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_register_class_constructs_on_demand() -> None:
        """connect_provider must instantiate from a class registered without an instance."""
        reset_provider_registry()
        reg = ProviderRegistry()
        reg.register_class(ProviderName.ANTHROPIC, ConcreteTestProvider)
        creds = ProviderCredentials(api_key="x")
        assert await reg.connect_provider(ProviderName.ANTHROPIC, creds) is True
        instance = reg.get(ProviderName.ANTHROPIC)
        assert isinstance(instance, ConcreteTestProvider)
        assert instance.is_connected

    @staticmethod
    def test_register_class_recorded_alongside_instance() -> None:
        """register() must record the concrete class in the internal class mapping.

        Verifies that ``_provider_classes[name]`` is set to ``type(instance)``
        when ``register(instance)`` is called, which is the fix introduced by
        F-0005 so that :meth:`connect_provider` can later reconstruct a
        provider from its class when the instance is absent.
        """
        reg = ProviderRegistry()
        instance = _make_provider()
        reg.register(instance)
        provider_classes: dict[ProviderName, type[LLMProviderBase]] = cast(
            "dict[ProviderName, type[LLMProviderBase]]",
            getattr(reg, "_provider_classes"),
        )
        recorded: type[LLMProviderBase] | None = provider_classes.get(ProviderName.ANTHROPIC)
        assert recorded is ConcreteTestProvider


class TestF0013DisconnectAllAggregates:
    """F-0013: disconnect_all wraps each provider and aggregates failures."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_aggregate_error_after_partial_failure() -> None:
        """All providers are processed; an aggregate ProviderError is raised."""
        reg = ProviderRegistry()
        failing = _DisconnectFails(
            RuntimeError("disc-fail"),
            provider_name=ProviderName.ANTHROPIC,
        )
        ok_provider = _DisconnectTracksCalls(provider_name=ProviderName.OPENAI)
        reg.register(failing)
        reg.register(ok_provider)
        with pytest.raises(ProviderError) as info:
            await reg.disconnect_all()
        details: dict[str, Any] = info.value.details or {}
        raw_errors: object = details.get("errors", [])
        assert isinstance(raw_errors, list)
        errors: list[dict[str, str]] = cast("list[dict[str, str]]", raw_errors)
        assert any(entry.get("provider") == ProviderName.ANTHROPIC.value for entry in errors)
        assert ok_provider.disconnect_called is True


class TestF0014ProviderErrorsCarryProviderName:
    """F-0014: ProviderError raised by registry includes provider_name."""

    @staticmethod
    def test_get_or_raise_unknown_carries_provider_name() -> None:
        """get_or_raise must include the missing provider name."""
        reg = ProviderRegistry()
        with pytest.raises(ProviderError) as info:
            reg.get_or_raise(ProviderName.OPENAI)
        assert info.value.provider_name == ProviderName.OPENAI.value

    @staticmethod
    def test_set_active_unconnected_carries_provider_name() -> None:
        """set_active for an unconnected provider must include the name."""
        reg = ProviderRegistry()
        reg.register(_make_provider())
        with pytest.raises(ProviderError) as info:
            reg.set_active(ProviderName.ANTHROPIC)
        assert info.value.provider_name == ProviderName.ANTHROPIC.value

    @pytest.mark.asyncio
    @staticmethod
    async def test_connect_no_credentials_carries_provider_name() -> None:
        """connect_provider raising for missing credentials must include the name."""
        reg = ProviderRegistry()
        reg.register(_make_provider())
        with pytest.raises(ProviderError) as info:
            await reg.connect_provider(ProviderName.ANTHROPIC)
        assert info.value.provider_name == ProviderName.ANTHROPIC.value


class TestF0015SingletonResetAndDI:
    """F-0015: reset hook plus credential_loader DI in get_provider_registry."""

    @staticmethod
    def test_reset_creates_fresh_singleton() -> None:
        """reset_provider_registry replaces the instance on next call."""
        reset_provider_registry()
        first = get_provider_registry()
        assert get_provider_registry() is first
        reset_provider_registry()
        second = get_provider_registry()
        assert second is not first

    @staticmethod
    def test_credential_loader_passed_at_first_construction() -> None:
        """The credential loader is recorded on first construction."""
        reset_provider_registry()
        loader: CredentialLoaderProtocol = _StaticCredentialLoader({})
        reg = get_provider_registry(credential_loader=loader)
        # subsequent calls return the same instance
        assert get_provider_registry() is reg


class TestF0016DisconnectClearsActive:
    """F-0016: disconnect_provider clears _active_provider when active."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnecting_active_clears_active() -> None:
        """The active provider must be cleared after disconnect."""
        reg = ProviderRegistry()
        provider = _DisconnectTracksCalls(provider_name=ProviderName.ANTHROPIC)
        reg.register(provider)
        reg.set_active(ProviderName.ANTHROPIC)
        assert reg.active_name == ProviderName.ANTHROPIC
        await reg.disconnect_provider(ProviderName.ANTHROPIC)
        assert reg.active_name is None
        assert reg.active is None
        assert provider.disconnect_called is True

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnecting_inactive_does_not_touch_active() -> None:
        """Disconnecting a non-active provider must keep active unchanged."""
        reg = ProviderRegistry()
        a = _DisconnectTracksCalls(provider_name=ProviderName.ANTHROPIC)
        b = _DisconnectTracksCalls(provider_name=ProviderName.OPENAI)
        reg.register(a)
        reg.register(b)
        reg.set_active(ProviderName.ANTHROPIC)
        await reg.disconnect_provider(ProviderName.OPENAI)
        assert reg.active_name == ProviderName.ANTHROPIC


class TestF0022ThreadSafeRegister:
    """F-0022: register/unregister/set_active are protected by an RLock."""

    @staticmethod
    def test_concurrent_register_does_not_corrupt_state() -> None:
        """Spawn many threads each calling register; final state is consistent."""
        reg = ProviderRegistry()
        names = list(ProviderName)

        errors: list[BaseException] = []

        def worker(idx: int) -> None:
            try:
                provider_name = names[idx % len(names)]
                reg.register(ConcreteTestProvider(provider_name=provider_name))
            except (RuntimeError, ProviderError) as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # Every provider name in the cycle should be present
        registered = set(reg.list_registered())
        assert registered == set(names)

    @pytest.mark.asyncio
    @staticmethod
    async def test_disconnect_all_with_no_providers_returns_cleanly() -> None:
        """disconnect_all on empty registry must not raise."""
        reg = ProviderRegistry()
        await reg.disconnect_all()


class TestGetActiveProviderHelper:
    """Cover the get_active_provider() public helper added with F-0022 plumbing."""

    @staticmethod
    def test_returns_none_when_unset() -> None:
        """get_active_provider returns None when no provider is active."""
        reg = ProviderRegistry()
        assert reg.get_active_provider() is None

    @staticmethod
    def test_returns_active_provider_when_set() -> None:
        """get_active_provider returns the registered active instance."""
        reg = ProviderRegistry()
        provider = _make_connected()
        reg.register(provider)
        reg.set_active(ProviderName.ANTHROPIC)
        assert reg.get_active_provider() is provider


class TestUnregisterDropsClassMapping:
    """unregister() should also forget the class mapping for that provider."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_unregister_then_connect_raises_not_registered() -> None:
        """After unregister, connect_provider must raise ProviderError."""
        reg = ProviderRegistry()
        reg.register(_make_provider())
        assert reg.unregister(ProviderName.ANTHROPIC) is True
        creds = ProviderCredentials(api_key="x")
        with pytest.raises(ProviderError):
            await reg.connect_provider(ProviderName.ANTHROPIC, creds)
