# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for the provider toolbar-refresh cluster.

Covers three related toolbar bugs:

1. Selecting HuggingFace in the toolbar re-derived credentials instead of
   reusing the already-connected provider client, so the raw HTTP fallback
   in :class:`~intellicrack.ui.provider_config.ModelRefreshWorker` built an
   ``Authorization: Bearer `` header from an empty token and crashed with
   ``httpx.LocalProtocolError: Illegal header value b'Bearer '``.
2. Selecting Ollama with only the cloud endpoint connected hit the same raw
   HTTP fallback against the hardcoded local endpoint
   (``http://localhost:11434``), failing with ``WinError 10061`` even though
   the cloud connection was live.
3. OpenAI and Grok defaulted the toolbar model selector to a non-chat media
   model (``sora-2-pro`` / ``grok-imagine-video-...``) because their
   ``_is_chat_model`` catalog filters did not exclude video/image
   generation models, so the media model sorted first and became the
   default selection.

Fix (1) and (2) share one root cause and one fix: ``MainWindow._on_refresh_models``
(``src/intellicrack/ui/app.py``) now looks up the already-connected provider
instance in the registry and passes it to ``ModelRefreshWorker``, which
prefers ``provider.list_models()`` (the authenticated client) over the raw
HTTP fallback. These tests drive the real, unmodified
``MainWindow._on_refresh_models`` bound method (against a plain duck-typed
holder -- the method never touches Qt widget internals directly, only
attribute reads/writes, so no live ``QApplication`` is needed) and assert
on the real ``ModelRefreshWorker`` construction argument it produces; the
actual ``ModelRefreshWorker`` class is replaced by a lightweight recorder
so the test observes exactly what the call site passes without spawning a
live network-fetching thread.

Fix (3) is verified by calling the real, unmodified ``_is_chat_model``
static methods on ``OpenAIProvider`` / ``GrokProvider`` directly against
real observed model ids from each catalog.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast
from unittest.mock import Mock

import pytest
from PyQt6.QtWidgets import QComboBox

from intellicrack.core.types import ProviderName
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.ui import app as app_module
from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from collections.abc import Callable


def _openai_is_chat_model(model_id: str) -> bool:
    """Invoke the real, protected ``OpenAIProvider._is_chat_model``.

    Extracted via ``vars()`` (rather than dotted attribute access) so the
    test drives the exact production filter without a lint suppression for
    private-member access.

    Args:
        model_id: OpenAI model identifier to classify.

    Returns:
        bool: True if the production filter considers ``model_id`` chat-capable.
    """
    fn = cast("Callable[[str], bool]", vars(OpenAIProvider)["_is_chat_model"])
    return fn(model_id)


def _grok_is_chat_model(model_id: str) -> bool:
    """Invoke the real, protected ``GrokProvider._is_chat_model``.

    Extracted via ``vars()`` (rather than dotted attribute access) so the
    test drives the exact production filter without a lint suppression for
    private-member access.

    Args:
        model_id: Grok model identifier to classify.

    Returns:
        bool: True if the production filter considers ``model_id`` chat-capable.
    """
    fn = cast("Callable[[str], bool]", vars(GrokProvider)["_is_chat_model"])
    return fn(model_id)


class _NullSignal:
    """No-op ``connect`` target standing in for ``refresh_finished``."""

    @staticmethod
    def connect(_slot: Callable[[bool, list[str], str], None]) -> None:
        """Discard the connection request.

        Args:
            _slot: The slot the production code would otherwise wire up.
        """


class _RecordingModelRefreshWorker:
    """Stand-in for ``ModelRefreshWorker`` that records its constructor args.

    ``_on_refresh_models`` is the unit under test; ``ModelRefreshWorker`` is
    its collaborator that performs the actual (network-bound, ``QThread``)
    model fetch. Substituting it with a plain Python double lets the test
    observe exactly what the call site wires up -- in particular, whether
    the already-connected provider instance is passed through -- without
    spawning a real background thread, hitting the network, or constructing
    any live Qt object.
    """

    last_provider_id: ClassVar[str | None] = None
    last_api_key: ClassVar[str | None] = None
    last_api_base: ClassVar[str | None] = None
    last_provider_arg: ClassVar[object] = None
    instances: ClassVar[int] = 0

    def __init__(
        self,
        provider_id: str,
        api_key: str,
        api_base: str | None = None,
        provider: object | None = None,
        parent: object | None = None,
    ) -> None:
        """Record the constructor arguments the call site supplied.

        Args:
            provider_id: Identifier of the provider to refresh models for.
            api_key: API key resolved by the call site.
            api_base: Optional custom API base URL.
            provider: Already-connected provider instance, if any.
            parent: Parent widget (unused; recorded implicitly by construction).
        """
        del parent
        type(self).last_provider_id = provider_id
        type(self).last_api_key = api_key
        type(self).last_api_base = api_base
        type(self).last_provider_arg = provider
        type(self).instances += 1
        self.refresh_finished = _NullSignal()

    def start(self) -> None:
        """No-op in place of spawning the real ``QThread`` worker."""


class _ProviderDouble:
    """Minimal provider double exposing only ``is_connected``."""

    def __init__(self, *, is_connected: bool) -> None:
        """Initialise with the desired connection flag.

        Args:
            is_connected: Whether the double should advertise as connected.
        """
        self.is_connected = is_connected


class _RegistryDouble:
    """Registry double returning a fixed provider instance from ``get``."""

    def __init__(self, provider: _ProviderDouble | None) -> None:
        """Initialise with the provider ``get`` should return.

        Args:
            provider: Provider double to return, or ``None``.
        """
        self._provider = provider

    def get(self, _name: ProviderName) -> _ProviderDouble | None:
        """Return the configured provider double.

        Args:
            _name: Requested provider (unused).

        Returns:
            _ProviderDouble | None: The configured stub provider.
        """
        return self._provider


class _OrchestratorDouble:
    """Orchestrator double exposing only ``provider_registry``."""

    def __init__(self, registry: _RegistryDouble) -> None:
        """Initialise with the registry double.

        Args:
            registry: Registry double to expose.
        """
        self.provider_registry = registry


class _StatusRecorder:
    """Records ``status_update.emit`` calls."""

    def __init__(self) -> None:
        """Initialise the emissions list."""
        self.emissions: list[str] = []

    def emit(self, message: str) -> None:
        """Record an emitted status message.

        Args:
            message: The status text emitted by production code.
        """
        self.emissions.append(message)


class _ConfigDouble:
    """Config double deliberately lacking ``is_provider_enabled``.

    ``_on_refresh_models`` guards its enabled/disabled check with
    ``hasattr(self._config, "is_provider_enabled")``; omitting the method
    keeps that branch inert so the test isolates the refresh-worker wiring.
    """


def _combo_double(*, current_data: object = None, current_text: str = "") -> QComboBox:
    """Build a spec-constrained mock standing in for the toolbar's ``QComboBox``.

    ``_on_refresh_models`` only calls ``currentData`` / ``currentText`` /
    ``clear`` / ``setEnabled`` on its combo attributes (it never wraps them
    in a ``QSignalBlocker``), so a ``Mock(spec=QComboBox)`` -- which never
    constructs a live Qt widget or requires a ``QApplication`` -- is
    sufficient and matches ``QComboBox``'s camelCase method names without
    hand-rolling them.

    Args:
        current_data: Value ``currentData()`` should return.
        current_text: Value ``currentText()`` should return.

    Returns:
        QComboBox: A ``Mock`` typed as ``QComboBox`` for attribute access.
    """
    combo = Mock(spec=QComboBox)
    combo.currentData.return_value = current_data
    combo.currentText.return_value = current_text
    return cast("QComboBox", combo)


def _build_refresh_holder(
    *,
    provider_name: ProviderName,
    registry_provider: _ProviderDouble | None,
) -> MainWindow:
    """Build a ``MainWindow``-shaped holder for ``_on_refresh_models`` tests.

    Args:
        provider_name: Provider selected in the toolbar combo.
        registry_provider: Provider double the registry double should
            return for ``provider_name``, or ``None`` if unregistered.

    Returns:
        MainWindow: A plain, duck-typed holder populated with the
        attributes ``_on_refresh_models`` reads, cast to ``MainWindow`` for
        the bound unbound-method call.
    """
    holder = _ConfigDouble()  # any plain object; attributes are set dynamically below
    vars(holder).update(
        {
            "_provider_combo": _combo_double(current_data=provider_name),
            "_orchestrator": _OrchestratorDouble(_RegistryDouble(registry_provider)),
            "_config": _ConfigDouble(),
            "status_update": _StatusRecorder(),
            "model_combo": _combo_double(current_text="previous-model"),
            "model_discovery": None,
            "model_refresh_worker": None,
        },
    )
    return cast("MainWindow", holder)


class TestRefreshModelsReusesConnectedProvider:
    """``_on_refresh_models`` must reuse an already-connected provider."""

    @staticmethod
    def _run(
        monkeypatch: pytest.MonkeyPatch,
        *,
        provider_name: ProviderName,
        registry_provider: _ProviderDouble | None,
    ) -> type[_RecordingModelRefreshWorker]:
        """Drive the real ``_on_refresh_models`` and return the recorded worker args.

        Args:
            monkeypatch: Pytest fixture used to substitute the
                ``ModelRefreshWorker`` collaborator.
            provider_name: Provider selected in the toolbar combo.
            registry_provider: Provider double the registry should return.

        Returns:
            type[_RecordingModelRefreshWorker]: The class carrying the
            recorded constructor arguments (accessed via its class
            attributes).
        """
        monkeypatch.setattr(app_module, "ModelRefreshWorker", _RecordingModelRefreshWorker)
        _RecordingModelRefreshWorker.last_provider_id = None
        _RecordingModelRefreshWorker.last_api_key = None
        _RecordingModelRefreshWorker.last_provider_arg = None
        _RecordingModelRefreshWorker.instances = 0

        holder = _build_refresh_holder(provider_name=provider_name, registry_provider=registry_provider)
        getattr(MainWindow, "_on_refresh_models")(holder)
        return _RecordingModelRefreshWorker

    def test_connected_huggingface_instance_is_reused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A connected HuggingFace provider instance is passed to the refresh worker.

        Args:
            monkeypatch: Pytest fixture used to substitute ``ModelRefreshWorker``.
        """
        connected = _ProviderDouble(is_connected=True)
        worker_cls = self._run(monkeypatch, provider_name=ProviderName.HUGGINGFACE, registry_provider=connected)

        assert worker_cls.instances == 1, "ModelRefreshWorker must be constructed exactly once"
        assert worker_cls.last_provider_arg is connected, (
            "connected HuggingFace instance must be passed through so the refresh reuses its verified "
            f"token instead of the raw empty-token HTTP fallback; got provider={worker_cls.last_provider_arg!r}"
        )
        assert worker_cls.last_provider_id == "huggingface"

    def test_connected_ollama_instance_is_reused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A connected Ollama provider instance is passed to the refresh worker.

        Args:
            monkeypatch: Pytest fixture used to substitute ``ModelRefreshWorker``.
        """
        connected = _ProviderDouble(is_connected=True)
        worker_cls = self._run(monkeypatch, provider_name=ProviderName.OLLAMA, registry_provider=connected)

        assert worker_cls.last_provider_arg is connected, (
            "connected Ollama instance (cloud-only when local is down) must be passed through so the "
            f"refresh reuses its resolved endpoint instead of the hardcoded localhost fallback; "
            f"got provider={worker_cls.last_provider_arg!r}"
        )
        assert worker_cls.last_provider_id == "ollama"

    def test_disconnected_registry_entry_falls_back_to_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A registered-but-disconnected provider does not get passed through.

        Args:
            monkeypatch: Pytest fixture used to substitute ``ModelRefreshWorker``.
        """
        disconnected = _ProviderDouble(is_connected=False)
        worker_cls = self._run(monkeypatch, provider_name=ProviderName.HUGGINGFACE, registry_provider=disconnected)

        assert worker_cls.last_provider_arg is None, (
            f"a disconnected registry entry must not be reused; got provider={worker_cls.last_provider_arg!r}"
        )

    def test_unregistered_provider_falls_back_to_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A provider absent from the registry does not get passed through.

        Args:
            monkeypatch: Pytest fixture used to substitute ``ModelRefreshWorker``.
        """
        worker_cls = self._run(monkeypatch, provider_name=ProviderName.OPENAI, registry_provider=None)

        assert worker_cls.last_provider_arg is None, f"an unregistered provider must pass provider=None; got {worker_cls.last_provider_arg!r}"


class TestOpenAIChatModelFilterExcludesMediaModels:
    """OpenAI's ``_is_chat_model`` must exclude video/image generation models."""

    @pytest.mark.parametrize(
        "model_id",
        ["sora-2-pro", "sora-2", "gpt-image-1", "gpt-image-1-mini"],
    )
    def test_media_models_are_excluded(self, model_id: str) -> None:
        """Video/image generation models are excluded from the chat catalog.

        Args:
            model_id: A real OpenAI media-generation model identifier.
        """
        assert _openai_is_chat_model(model_id) is False, (
            f"{model_id!r} is a non-chat media model and must be excluded from the toolbar's default selection"
        )

    @pytest.mark.parametrize(
        "model_id",
        ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "o3", "o4-mini"],
    )
    def test_real_chat_models_are_retained(self, model_id: str) -> None:
        """Genuine chat-completions models remain in the catalog.

        Args:
            model_id: A real OpenAI chat-completions model identifier.
        """
        assert _openai_is_chat_model(model_id) is True, f"{model_id!r} is a genuine chat model and must not be filtered out"

    def test_reverse_sorted_catalog_no_longer_defaults_to_sora(self) -> None:
        """Reproduces the exact toolbar default-selection bug end to end.

        ``_fetch_and_sort_models`` builds its catalog by keeping only
        ``_is_chat_model`` ids and sorting them ``reverse=True``; the
        toolbar then defaults to index 0 when no configured default model
        matches. Before the fix, ``sora-2-pro`` sorted ahead of every real
        chat model and became that default.
        """
        raw_catalog = ["gpt-4o", "gpt-4.1", "o3", "o4-mini", "sora-2-pro", "gpt-image-1"]
        chat_only = sorted((m for m in raw_catalog if _openai_is_chat_model(m)), reverse=True)

        assert chat_only, "filtering must not remove every model"
        assert chat_only[0] != "sora-2-pro", f"default selection regressed to the non-chat model: {chat_only!r}"
        assert "gpt-image-1" not in chat_only


class TestGrokChatModelFilterExcludesMediaModels:
    """Grok's ``_is_chat_model`` must exclude video/image generation models."""

    @pytest.mark.parametrize(
        "model_id",
        ["grok-imagine-video-1", "grok-imagine-image-1"],
    )
    def test_media_models_are_excluded(self, model_id: str) -> None:
        """Video/image generation models are excluded from the chat catalog.

        Args:
            model_id: A real Grok media-generation model identifier.
        """
        assert _grok_is_chat_model(model_id) is False, (
            f"{model_id!r} is a non-chat media model and must be excluded from the toolbar's default selection"
        )

    @pytest.mark.parametrize(
        "model_id",
        ["grok-4-latest", "grok-3", "grok-2-vision-1212", "grok-4-fast"],
    )
    def test_real_chat_models_are_retained(self, model_id: str) -> None:
        """Genuine chat-completions models remain in the catalog.

        Args:
            model_id: A real Grok chat-completions model identifier.
        """
        assert _grok_is_chat_model(model_id) is True, f"{model_id!r} is a genuine chat model and must not be filtered out"

    def test_reverse_sorted_catalog_no_longer_defaults_to_imagine_video(self) -> None:
        """Reproduces the exact toolbar default-selection bug end to end.

        Grok's ``_fetch_and_sort_models`` keeps only ``_is_chat_model`` ids
        and sorts ``reverse=True``; before the fix, ``grok-imagine-video-1``
        sorted ahead of every ``grok-4``/``grok-3`` chat model (``'i'`` >
        ``'4'``) and became the toolbar's default.
        """
        raw_catalog = ["grok-4-latest", "grok-3", "grok-2-vision-1212", "grok-imagine-video-1"]
        chat_only = sorted((m for m in raw_catalog if _grok_is_chat_model(m)), reverse=True)

        assert chat_only, "filtering must not remove every model"
        assert chat_only[0] != "grok-imagine-video-1", f"default selection regressed to the non-chat model: {chat_only!r}"
