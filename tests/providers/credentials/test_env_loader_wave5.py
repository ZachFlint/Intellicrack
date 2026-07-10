# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 falsifiable gates for env_loader.py — ops #92 #106 #107 #108 #110 #112 #116 #123 #124 #125 #126 #127.

Every test here is a REAL gate: a named one-line mutation in the production
code would make the test red.  Filesystem-boundary patches (read_text / Path.open)
are used only where the finding explicitly requires it; the loader's own
parsing and lookup logic always executes against real inputs.
"""

from __future__ import annotations

import pathlib
import stat
from typing import TYPE_CHECKING, Any, cast

import pytest

import intellicrack.credentials.env_loader as _env_loader_mod
from intellicrack.core.types import ProviderName
from intellicrack.credentials.env_loader import (
    CredentialLoader,
    create_env_template,
    get_api_key_env_var_mapping,
    get_credential_loader,
)


if TYPE_CHECKING:
    from collections.abc import Callable

_decode_double_quoted: Callable[[str], str] = cast(Any, _env_loader_mod)._decode_double_quoted


_TEST_OSERR: str = "test-ioerr-gate"

_ALL_PROVIDER_VARS: tuple[str, ...] = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENAI_API_BASE",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT",
    "GOOGLE_API_KEY",
    "GOOGLE_CLOUD_PROJECT",
    "GEMINI_API_KEY",
    "OLLAMA_API_KEY",
    "OLLAMA_HOST",
    "OPENROUTER_API_KEY",
    "HUGGINGFACE_API_TOKEN",
    "HUGGINGFACE_API_BASE",
    "XAI_API_KEY",
    "XAI_API_BASE",
    "LOCAL_TRANSFORMERS_HF_TOKEN",
    "LOCAL_TRANSFORMERS_CACHE_DIR",
)


def _clear_all_provider_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every known provider API-key variable from os.environ.

    The test sandbox container ships live provider keys in os.environ.
    CredentialLoader._get_var falls back to os.environ, so tests that assert
    "no credential" or "exactly one credential" must strip ambient keys first.

    Args:
        monkeypatch: pytest monkeypatch fixture used to delete the variables.
    """
    for var in _ALL_PROVIDER_VARS:
        monkeypatch.delenv(var, raising=False)


def _read_text_raise(self: pathlib.Path, **_kwargs: object) -> str:
    raise OSError(_TEST_OSERR + str(self))


def _open_raise(self: pathlib.Path, mode: str = "r", **_kwargs: object) -> object:
    raise OSError(_TEST_OSERR + mode + str(self))


def test_decode_double_quoted_unknown_escape() -> None:
    """_decode_double_quoted drops the backslash and keeps the char for unknown escapes.

    The input contains a literal backslash followed by the letter q, which is not
    a recognised escape sequence.  The documented behaviour is backslash-dropped,
    char-kept, so the pair must produce the single character 'q'.

    Mutation: changing result.append(nxt) to result.append(chr(92) + nxt)
    in the else-branch of _decode_double_quoted keeps the backslash, producing
    eight output characters instead of seven and turning this test red.
    """
    result = _decode_double_quoted("val\\qend")
    assert result == "valqend"


def test_load_env_file_missing_path_returns_none(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_env_file silently returns when the env file path does not exist.

    CredentialLoader must not raise when the .env file is absent; it must
    initialise with an empty credential set so that get_credentials returns None.

    Mutation: removing the ``if not self.env_path.exists(): return`` guard in
    _load_env_file would let read_text raise FileNotFoundError out of __init__,
    turning this test red.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    nonexistent = tmp_path / "missing.env"
    loader = CredentialLoader(env_path=nonexistent)
    assert loader.get_credentials(ProviderName.ANTHROPIC) is None


def test_load_env_file_read_error_no_raise(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_env_file swallows OSError from read_text without propagating it.

    When the .env file exists but cannot be read (e.g. OS-level read error),
    the loader must complete __init__ without raising and must return no
    credentials because _env_vars remains empty.

    Mutation: removing the ``except OSError`` handler in _load_env_file (or
    replacing it with a bare ``raise``) would let the error escape __init__,
    turning this test red.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-api03-real\n", encoding="utf-8")

    monkeypatch.setattr(pathlib.Path, "read_text", _read_text_raise)

    loader = CredentialLoader(env_path=env_file)
    assert loader.get_credentials(ProviderName.ANTHROPIC) is None


def test_get_credentials_alias_lookup(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_credentials resolves GEMINI_API_KEY as an alias for ProviderName.GOOGLE.

    When only the alias variable is present in the .env file (primary
    GOOGLE_API_KEY is absent from both the file and os.environ), get_credentials
    must still return the credential found via alias lookup.

    Mutation: removing the alias loop in get_credentials leaves api_key as None
    and returns None instead of a ProviderCredentials, turning this test red.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("GEMINI_API_KEY=AIzaTestXXXX\n", encoding="utf-8")

    loader = CredentialLoader(env_path=env_file)
    creds = loader.get_credentials(ProviderName.GOOGLE)

    assert creds is not None
    assert creds.api_key == "AIzaTestXXXX"


def test_all_provider_names_in_mapping_making_unknown_branch_dead() -> None:
    """Every ProviderName member has a PROVIDER_MAPPINGS entry, so the early-return is dead.

    The branch ``if mapping is None: return None`` at env_loader.py:396 can never
    be reached because the ProviderName enum is closed and all its members are keys
    in PROVIDER_MAPPINGS.  This test asserts the structural invariant.

    Mutation: adding a new ProviderName member without a corresponding
    PROVIDER_MAPPINGS entry would break the invariant and turn this test red.
    """
    all_names: set[ProviderName] = set(ProviderName)
    mapped_names: set[ProviderName] = set(CredentialLoader.PROVIDER_MAPPINGS.keys())
    assert all_names == mapped_names


def test_save_to_env_file_read_error_propagates(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """save_to_env_file propagates OSError when the existing .env cannot be read.

    The method reads the current .env content to preserve comments; the except
    block explicitly re-raises the OSError rather than swallowing it.

    Mutation: replacing the bare ``raise`` in the read except block with
    ``return`` would swallow the error; the pytest.raises context would see no
    exception and turn this test red.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING=old_value\n", encoding="utf-8")
    loader = CredentialLoader(env_path=env_file)

    monkeypatch.setattr(pathlib.Path, "open", _open_raise)

    with pytest.raises(OSError, match=_TEST_OSERR):
        loader.save_to_env_file("ANTHROPIC_API_KEY", "sk-ant-api03-test")


def test_save_to_env_file_write_error_propagates(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """save_to_env_file propagates OSError when the .env file cannot be written.

    Making the .env file read-only allows the read phase (which only opens for
    'r') to succeed while the write phase (which opens for 'w') raises
    PermissionError, a subclass of OSError.  The except block re-raises.

    Mutation: replacing the bare ``raise`` in the write except block with
    ``return`` would swallow the error; the pytest.raises context would see no
    exception and turn this test red.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING=old_value\n", encoding="utf-8")
    loader = CredentialLoader(env_path=env_file)

    env_file.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    try:
        with pytest.raises(OSError, match=r"(?i)access|permission|denied"):
            loader.save_to_env_file("ANTHROPIC_API_KEY", "sk-ant-api03-test")
    finally:
        env_file.chmod(stat.S_IWRITE | stat.S_IREAD)


def test_get_api_key_env_var_mapping_exact_values() -> None:
    """get_api_key_env_var_mapping returns exact env var names for every provider.

    The function derives its output directly from PROVIDER_MAPPINGS, so it must
    reproduce the precise api_key_var string for each provider key.

    Mutation: changing any api_key_var in PROVIDER_MAPPINGS (e.g. renaming
    'ANTHROPIC_API_KEY' to 'ANTHROPIC_KEY') would change the returned value
    and turn this test red.
    """
    mapping = get_api_key_env_var_mapping()

    assert mapping["anthropic"] == "ANTHROPIC_API_KEY"
    assert mapping["openai"] == "OPENAI_API_KEY"
    assert mapping["google"] == "GOOGLE_API_KEY"
    assert mapping["ollama"] == "OLLAMA_API_KEY"
    assert mapping["openrouter"] == "OPENROUTER_API_KEY"
    assert mapping["huggingface"] == "HUGGINGFACE_API_TOKEN"
    assert mapping["grok"] == "XAI_API_KEY"
    assert mapping["local_transformers"] == "LOCAL_TRANSFORMERS_HF_TOKEN"
    assert set(mapping.keys()) == {p.value for p in ProviderName}


def test_create_env_template_contains_required_placeholders(tmp_path: pathlib.Path) -> None:
    """create_env_template writes a file whose content includes each provider placeholder.

    The function writes a template .env file to the given path.  The content must
    contain KEY= placeholder lines for at least the four primary cloud providers.

    Mutation: removing any placeholder line from the template string in
    create_env_template would cause the corresponding assertion to turn red.

    Args:
        tmp_path: pytest temporary directory.
    """
    template_path = tmp_path / ".env.example"
    create_env_template(template_path)
    content = template_path.read_text(encoding="utf-8")

    assert "ANTHROPIC_API_KEY=" in content
    assert "OPENAI_API_KEY=" in content
    assert "GOOGLE_API_KEY=" in content
    assert "OPENROUTER_API_KEY=" in content


def test_get_credential_loader_returns_singleton() -> None:
    """get_credential_loader() returns the identical CredentialLoader on every call.

    The function is decorated with @functools.lru_cache(maxsize=1).  Every call
    after the first must return the same cached object rather than constructing
    a new CredentialLoader.

    Mutation: removing the @functools.lru_cache decorator causes each call to
    allocate a fresh CredentialLoader, so ``result1 is result2`` becomes False
    and this test turns red.
    """
    get_credential_loader.cache_clear()
    try:
        result1 = get_credential_loader()
        result2 = get_credential_loader()
        assert result1 is result2
    finally:
        get_credential_loader.cache_clear()


def test_reload_picks_up_new_key(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """reload() causes list_configured_providers() to reflect keys added after construction.

    Writing an Anthropic key to the .env file AFTER the loader is constructed must
    not appear in list_configured_providers() until reload() is called.  After
    reload(), the provider must be present in the result.

    Mutation: removing ``self._env_vars.clear()`` from reload() preserves stale
    state so the post-reload assertion still returns [] and turns red.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")

    loader = CredentialLoader(env_path=env_file)
    assert ProviderName.ANTHROPIC not in loader.list_configured_providers()

    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-api03-testkey\n", encoding="utf-8")
    loader.reload()

    assert ProviderName.ANTHROPIC in loader.list_configured_providers()


def test_list_configured_providers_exact_single_provider(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """list_configured_providers returns only the one provider whose key is present.

    Writing exactly one Anthropic API key to a controlled .env file, with all
    other provider variables absent from os.environ, must produce a list
    containing only ProviderName.ANTHROPIC.

    Mutation: replacing list_configured_providers with a function that returns
    all ProviderName members would include providers beyond ANTHROPIC and turn
    the ``== [ProviderName.ANTHROPIC]`` assertion red.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-api03-testkey\n", encoding="utf-8")

    loader = CredentialLoader(env_path=env_file)
    configured = loader.list_configured_providers()

    assert configured == [ProviderName.ANTHROPIC]
