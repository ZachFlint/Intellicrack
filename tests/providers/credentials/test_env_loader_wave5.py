# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for env_loader.py.

Filesystem patches (read_text / Path.open) are used only where the I/O failure is the behavior under test. The loader's own
parsing and lookup logic always executes against real inputs.
"""

from __future__ import annotations

import pathlib
import stat
import sys
from typing import TYPE_CHECKING, Any, cast

import pytest

import intellicrack.credentials.env_loader as _env_loader_mod
from intellicrack.credentials.env_loader import (
    CredentialLoader,
    create_env_template,
    get_api_key_env_var_mapping,
    get_credential_loader,
)


if TYPE_CHECKING:
    from collections.abc import Callable
from intellicrack.providers import ids as provider_ids


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

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    nonexistent = tmp_path / "missing.env"
    loader = CredentialLoader(env_path=nonexistent)
    assert loader.get_credentials(provider_ids.ANTHROPIC) is None


def test_load_env_file_read_error_no_raise(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_env_file swallows OSError from read_text without propagating it.

    When the .env file exists but cannot be read (e.g. OS-level read error),
    the loader must complete __init__ without raising and must return no
    credentials because _env_vars remains empty.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-api03-real\n", encoding="utf-8")

    monkeypatch.setattr(pathlib.Path, "read_text", _read_text_raise)

    loader = CredentialLoader(env_path=env_file)
    assert loader.get_credentials(provider_ids.ANTHROPIC) is None


def test_get_credentials_alias_lookup(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_credentials resolves GEMINI_API_KEY as an alias for provider_ids.GOOGLE.

    When only the alias variable is present in the .env file (primary
    GOOGLE_API_KEY is absent from both the file and os.environ), get_credentials
    must still return the credential found via alias lookup.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("GEMINI_API_KEY=AIzaTestXXXX\n", encoding="utf-8")

    loader = CredentialLoader(env_path=env_file)
    creds = loader.get_credentials(provider_ids.GOOGLE)

    assert creds is not None
    assert creds.api_key == "AIzaTestXXXX"


def test_all_provider_names_in_mapping_making_unknown_branch_dead() -> None:
    """Every provider id member has a PROVIDER_MAPPINGS entry, so the early-return is dead.

    The branch ``if mapping is None: return None`` at env_loader.py:396 can never
    be reached because the provider id enum is closed and all its members are keys
    in PROVIDER_MAPPINGS.  This test asserts the structural invariant.
    """
    all_names: set[str] = set(provider_ids.BUILTIN_PROVIDER_IDS)
    mapped_names: set[str] = set(CredentialLoader.PROVIDER_MAPPINGS.keys())
    assert all_names == mapped_names


def test_save_to_env_file_read_error_propagates(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """save_to_env_file propagates OSError when the existing .env cannot be read.

    The method reads the current .env content to preserve comments; the except
    block explicitly re-raises the OSError rather than swallowing it.

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


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows refuses to replace a read-only .env file; POSIX os.replace swaps it in through the directory",
)
def test_save_to_env_file_write_error_propagates(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """save_to_env_file propagates OSError when the .env file cannot be written.

    Making the .env file read-only allows the read phase to succeed while the
    write phase's atomic replace of the file raises PermissionError, a
    subclass of OSError, because Windows will not replace a read-only file.
    The except block re-raises.

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
    assert set(mapping.keys()) == set(provider_ids.BUILTIN_PROVIDER_IDS)


def test_create_env_template_contains_required_placeholders(tmp_path: pathlib.Path) -> None:
    """create_env_template writes a file whose content includes each provider placeholder.

    The function writes a template .env file to the given path.  The content must
    contain KEY= placeholder lines for at least the four primary cloud providers.

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

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")

    loader = CredentialLoader(env_path=env_file)
    assert provider_ids.ANTHROPIC not in loader.list_configured_providers()

    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-api03-testkey\n", encoding="utf-8")
    loader.reload()

    assert provider_ids.ANTHROPIC in loader.list_configured_providers()


def test_list_configured_providers_exact_single_provider(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """list_configured_providers returns only the one provider whose key is present.

    Writing exactly one Anthropic API key to a controlled .env file, with all
    other provider variables absent from os.environ, must produce a list
    containing only provider_ids.ANTHROPIC.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.
    """
    _clear_all_provider_vars(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-ant-api03-testkey\n", encoding="utf-8")

    loader = CredentialLoader(env_path=env_file)
    configured = loader.list_configured_providers()

    assert configured == [provider_ids.ANTHROPIC]
