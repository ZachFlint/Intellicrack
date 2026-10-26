# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Grok/xAI API key resolution in the provider settings widget.

The widget's resolved API key must agree with the source that ``CredentialStore.get_source`` reports. ``ProviderSettingsWidget._resolve_env_api_key`` looks the key up through ``get_credential_loader().get_credentials(...)``, the same environment-variable mapping (``CredentialLoader.PROVIDER_MAPPINGS``) the other credential consumers use, so the value path and the source path name the same variable for every provider.

These tests drive the real, unmodified ``_resolve_env_api_key`` method (extracted via ``vars()`` per the project pattern in ``tests/providers/test_provider_refresh_toolbar_bugfixes.py``, so no live ``QApplication`` is required) against a real temporary ``.env`` file, and cross-check the result against the real ``CredentialStore.get_source``/``CredentialStore.get`` path so the two can be asserted to agree.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialSource, CredentialStore
from intellicrack.providers import ids as provider_ids
from intellicrack.ui import provider_config as provider_config_module
from intellicrack.ui.provider_config import ProviderSettingsWidget


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_FAKE_XAI_TOKEN = "xai-" + ("x" * 80)
_FAKE_GROK_ALIAS_TOKEN = "xai-" + ("g" * 80)
_FAKE_OPENAI_TOKEN = "sk-" + ("a" * 81)

assert len(_FAKE_XAI_TOKEN) == 84
assert len(_FAKE_GROK_ALIAS_TOKEN) == 84


class _StubProviderWidget:
    """Duck-typed stand-in carrying only what ``_resolve_env_api_key`` reads.

    ``_resolve_env_api_key`` only reads ``self.provider_id`` -- it never
    touches a Qt widget attribute -- so a real ``ProviderSettingsWidget``
    (which would require a live ``QApplication`` to construct) is
    unnecessary; a plain object with the same attribute name exercises the
    exact production method body.
    """

    def __init__(self, provider_id: str) -> None:
        """Initialize the stub with the given provider id.

        Args:
            provider_id: Provider identifier to expose as ``self.provider_id``.
        """
        self.provider_id = provider_id


def _resolve_env_api_key(provider_id: str) -> str:
    """Invoke the real, unmodified ``ProviderSettingsWidget._resolve_env_api_key``.

    Extracted via ``vars()`` (rather than dotted attribute access) so the
    test drives the exact production method without needing to construct a
    live ``ProviderSettingsWidget`` (which requires a ``QApplication``).

    Args:
        provider_id: Provider identifier to resolve the API key for.

    Returns:
        str: Whatever the production method returns for that provider id.
    """
    fn = cast("Callable[[Any], str]", vars(ProviderSettingsWidget)["_resolve_env_api_key"])
    return fn(_StubProviderWidget(provider_id))


def _write_env_file(tmp_path: Path, content: str) -> Path:
    """Write a real temporary ``.env`` file with the given content.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.
        content: Raw ``.env`` file contents to write.

    Returns:
        Path: Path to the written temporary ``.env`` file.
    """
    env_path = tmp_path / ".env"
    env_path.write_text(content, encoding="utf-8")
    return env_path


def _make_keyring_free_store(loader: CredentialLoader) -> CredentialStore:
    """Build a CredentialStore that always falls back to ``loader``.

    Forces ``keyring_available`` to False before it is ever queried, so the
    store's credential resolution is deterministically driven only by the
    supplied fallback loader and never touches the real OS keyring.

    Args:
        loader: The CredentialLoader the store should fall back to.

    Returns:
        CredentialStore: A store wired to ``loader`` with keyring disabled.
    """
    store = CredentialStore(fallback_loader=loader)
    store_any: Any = cast(Any, store)
    store_any._keyring_checked = True
    store_any._keyring_available = False
    return store


@pytest.fixture
def clean_grok_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove ambient Grok/xAI/OpenAI credential variables from ``os.environ``.

    ``CredentialLoader._get_var`` falls back to ``os.environ`` when a name is
    absent from the parsed ``.env`` file, and loading a real temp ``.env``
    also writes its keys into ``os.environ``. Clearing these first keeps each
    test's real temporary file the sole source of truth, and pytest's
    monkeypatch fixture restores whatever was ambient afterward.

    Args:
        monkeypatch: Pytest fixture used to delete and later restore the variables.
    """
    for name in ("XAI_API_KEY", "GROK_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.usefixtures("clean_grok_env")
def test_resolve_env_api_key_grok_reads_xai_api_key_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_resolve_env_api_key("grok")`` returns the value of ``XAI_API_KEY``.

    Reproduces the exact reported repro: a real ``.env`` file defines BOTH
    ``XAI_API_KEY`` and ``GROK_API_KEY`` with distinct 84-char values. Before
    the fix, Grok was entirely absent from ``_load_settings``'s hand-rolled
    ``env_vars`` dict, so the widget's API-key field -- and therefore this
    method's result -- was always empty regardless of ``.env`` contents.

    Revert target: restore the original ``_load_settings`` body (the
    six-entry ``env_vars`` dict with no ``"grok"`` key, reading
    ``os.environ.get(env_vars[self.provider_id], "")`` and removing the
    ``_resolve_env_api_key`` method) in
    ``src/intellicrack/ui/provider_config.py``. With that reverted,
    ``vars(ProviderSettingsWidget)["_resolve_env_api_key"]`` raises
    ``KeyError`` because the method no longer exists, failing this test.
    """
    env_path = _write_env_file(
        tmp_path,
        f"XAI_API_KEY={_FAKE_XAI_TOKEN}\nGROK_API_KEY={_FAKE_GROK_ALIAS_TOKEN}\n",
    )
    monkeypatch.setattr(
        provider_config_module,
        "get_credential_loader",
        lambda: CredentialLoader(env_path=env_path),
    )

    resolved = _resolve_env_api_key("grok")

    assert resolved == _FAKE_XAI_TOKEN
    assert resolved


@pytest.mark.usefixtures("clean_grok_env")
def test_resolve_env_api_key_grok_matches_store_get_source_env_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The widget's resolved Grok API key agrees with ``CredentialStore.get_source``.

    ``CredentialStore.get_source`` reports ``CredentialSource.ENV_FILE`` for Grok, and the widget's resolved value must be the non-empty key from that same file. This test drives the real ``CredentialStore`` (keyring disabled) and the real ``_resolve_env_api_key`` against one temporary ``.env`` file and asserts both agree: source is ENV_FILE and the resolved value is non-empty and correct.

    Revert target: restoring the grok-less ``env_vars`` dict in ``_load_settings`` (and removing ``_resolve_env_api_key``) makes ``resolved_key`` empty while ``source`` still reports ``CredentialSource.ENV_FILE``, so the ``resolved_key == _FAKE_XAI_TOKEN`` assertion fails.
    """
    env_path = _write_env_file(tmp_path, f"XAI_API_KEY={_FAKE_XAI_TOKEN}\n")
    monkeypatch.setattr(
        provider_config_module,
        "get_credential_loader",
        lambda: CredentialLoader(env_path=env_path),
    )
    store = _make_keyring_free_store(CredentialLoader(env_path=env_path))

    source = asyncio.run(store.get_source(provider_ids.GROK))
    resolved_key = _resolve_env_api_key("grok")

    assert source is CredentialSource.ENV_FILE
    assert resolved_key == _FAKE_XAI_TOKEN


@pytest.mark.usefixtures("clean_grok_env")
def test_resolve_env_api_key_openai_unaffected_by_grok_fix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OpenAI's API key still resolves correctly through the canonical lookup.

    Guards the providers that already worked (OpenAI, Anthropic, Google, OpenRouter, HuggingFace, Local Transformers) against a regression in the shared mapping.

    This is a non-regression guard rather than a check of the Grok change: the Grok revert recipe above does not touch OpenAI's mapping.
    """
    env_path = _write_env_file(tmp_path, f"OPENAI_API_KEY={_FAKE_OPENAI_TOKEN}\n")
    monkeypatch.setattr(
        provider_config_module,
        "get_credential_loader",
        lambda: CredentialLoader(env_path=env_path),
    )

    resolved = _resolve_env_api_key("openai")

    assert resolved == _FAKE_OPENAI_TOKEN
