# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for provider endpoint settings persisted in the ``.env`` file.

``.env`` is the source of truth for every provider's API key, base URL and
organization. These gates drive the real :class:`CredentialLoader` against real
temporary ``.env`` files and the real process environment, and fail when:

* a saved OpenRouter base URL does not reach its credentials (it had no
  ``OPENROUTER_API_BASE`` mapping, so gateways were silently ignored);
* a keyless provider loses its saved host because no API key is configured;
* a blank saved value surfaces as an empty base URL instead of "unset";
* persisting a field does not write it where the next launch reads it, copies
  an inherited operating-system value into the file, or fails to remove a
  cleared value while restoring the value the operating system supplied;
* clearing an API key leaves a provider-owned alias behind or deletes another
  provider's key;
* the global loader resolves a different ``.env`` than startup does on an
  installed build (it searched the working directory first).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.config import get_env_file
from intellicrack.credentials.env_loader import (
    CredentialField,
    CredentialLoader,
    EnvPersistAction,
    get_credential_loader,
)
from intellicrack.providers import ids as provider_ids
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root


if TYPE_CHECKING:
    from pathlib import Path


_OPENAI_KEY = "sk-" + ("e" * 48)
_GOOGLE_KEY = "AIza" + ("g" * 35)
_GEMINI_ALIAS_KEY = "AIza" + ("h" * 35)
_HF_TOKEN = "hf_" + ("t" * 34)
_LOCAL_TRANSFORMERS_TOKEN = "hf_" + ("l" * 34)
_OS_BASE_URL = "https://os-level-gateway.example/v1"
_SAVED_BASE_URL = "https://api.venice.example/api/v1"


@pytest.fixture(autouse=True)
def clean_provider_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every gate from an environment without provider variables.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    isolate_provider_environment(monkeypatch)


def _write_env(tmp_path: Path, content: str) -> Path:
    """Write a real ``.env`` file.

    Args:
        tmp_path: Per-test temporary directory.
        content: File content.

    Returns:
        Path: The written file.
    """
    env_path = tmp_path / ".env"
    env_path.write_text(content, encoding="utf-8")
    return env_path


def test_openrouter_base_url_saved_in_env_reaches_credentials(tmp_path: Path) -> None:
    """A saved ``OPENROUTER_API_BASE`` is part of OpenRouter's credentials.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = _write_env(tmp_path, f"OPENROUTER_API_KEY=sk-or-{'r' * 40}\nOPENROUTER_API_BASE={_SAVED_BASE_URL}\n")

    credentials = CredentialLoader(env_path).get_credentials(provider_ids.OPENROUTER)

    assert credentials is not None
    assert credentials.api_base == _SAVED_BASE_URL


def test_keyless_provider_connect_credentials_keep_saved_host(tmp_path: Path) -> None:
    """A keyless provider keeps its saved host; a keyed provider still needs its key.

    Args:
        tmp_path: Per-test temporary directory.
    """
    host = "http://10.20.30.40:11434"
    loader = CredentialLoader(_write_env(tmp_path, f"OLLAMA_HOST={host}\n"))

    assert loader.get_credentials(provider_ids.OLLAMA) is None
    keyless = loader.get_connect_credentials(provider_ids.OLLAMA, api_key_optional=True)
    assert keyless is not None
    assert keyless.api_key is None
    assert keyless.api_base == host
    assert loader.get_connect_credentials(provider_ids.OPENAI, api_key_optional=False) is None


def test_blank_saved_endpoint_values_resolve_to_unset(tmp_path: Path) -> None:
    """Blank ``OPENAI_API_BASE``/``OPENAI_ORGANIZATION`` entries mean "not set", never ``""``.

    An empty base URL handed to the OpenAI SDK replaces its default endpoint
    with an unusable one.

    Args:
        tmp_path: Per-test temporary directory.
    """
    loader = CredentialLoader(_write_env(tmp_path, f"OPENAI_API_KEY={_OPENAI_KEY}\nOPENAI_API_BASE=\nOPENAI_ORGANIZATION=\n"))

    credentials = loader.get_credentials(provider_ids.OPENAI)

    assert credentials is not None
    assert credentials.api_base is None
    assert credentials.organization_id is None


def test_persisted_endpoint_fields_are_read_by_the_next_launch(tmp_path: Path) -> None:
    """Fields persisted through one loader are resolved by a fresh loader on the same file.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = _write_env(tmp_path, f"# credentials\nOPENAI_API_KEY={_OPENAI_KEY}\n")
    loader = CredentialLoader(env_path)

    assert loader.persist_field(provider_ids.OPENAI, CredentialField.API_BASE, f"  {_SAVED_BASE_URL}  ") is EnvPersistAction.WRITTEN
    assert loader.persist_field(provider_ids.OPENAI, CredentialField.ORGANIZATION_ID, "org-venice") is EnvPersistAction.WRITTEN
    assert loader.persist_field(provider_ids.OPENAI, CredentialField.ORGANIZATION_ID, "org-venice") is EnvPersistAction.UNCHANGED

    lines = env_path.read_text(encoding="utf-8").splitlines()
    assert "# credentials" in lines
    assert sum(line.startswith("OPENAI_API_BASE=") for line in lines) == 1
    assert "OPENAI_ORGANIZATION=org-venice" in lines

    next_launch = CredentialLoader(env_path).get_credentials(provider_ids.OPENAI)
    assert next_launch is not None
    assert next_launch.api_key == _OPENAI_KEY
    assert next_launch.api_base == _SAVED_BASE_URL
    assert next_launch.organization_id == "org-venice"


def test_inherited_process_value_is_not_copied_into_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Saving a base URL equal to the operating-system value leaves ``.env`` untouched.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setenv("OPENAI_API_BASE", _OS_BASE_URL)
    env_path = _write_env(tmp_path, f"OPENAI_API_KEY={_OPENAI_KEY}\n")
    loader = CredentialLoader(env_path)

    action = loader.persist_field(provider_ids.OPENAI, CredentialField.API_BASE, _OS_BASE_URL)

    assert action is EnvPersistAction.UNCHANGED
    assert "OPENAI_API_BASE" not in env_path.read_text(encoding="utf-8")


def test_clearing_saved_base_url_removes_line_and_restores_os_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Clearing a saved base URL deletes it from ``.env`` and the OS-level value applies again.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setenv("OPENAI_API_BASE", _OS_BASE_URL)
    env_path = tmp_path / ".env"
    env_path.write_bytes(
        f"# header\r\nOPENAI_API_KEY={_OPENAI_KEY}\r\nexport OPENAI_API_BASE={_SAVED_BASE_URL}\r\nOPENAI_ORGANIZATION=org-keep\r\n".encode(),
    )
    loader = CredentialLoader(env_path)
    assert os.environ["OPENAI_API_BASE"] == _SAVED_BASE_URL
    assert loader.get_field(provider_ids.OPENAI, CredentialField.API_BASE) == _SAVED_BASE_URL

    action = loader.persist_field(provider_ids.OPENAI, CredentialField.API_BASE, "   ")

    assert action is EnvPersistAction.REMOVED
    assert env_path.read_bytes() == f"# header\r\nOPENAI_API_KEY={_OPENAI_KEY}\r\nOPENAI_ORGANIZATION=org-keep\r\n".encode()
    assert os.environ["OPENAI_API_BASE"] == _OS_BASE_URL
    assert loader.get_field(provider_ids.OPENAI, CredentialField.API_BASE) == _OS_BASE_URL

    next_launch = CredentialLoader(env_path).get_credentials(provider_ids.OPENAI)
    assert next_launch is not None
    assert next_launch.api_base == _OS_BASE_URL
    assert next_launch.organization_id == "org-keep"


def test_clearing_value_absent_from_os_environment_unsets_the_variable(tmp_path: Path) -> None:
    """With no OS-level value, clearing a saved base URL removes the variable entirely.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = _write_env(tmp_path, f"OPENAI_API_KEY={_OPENAI_KEY}\nOPENAI_API_BASE={_SAVED_BASE_URL}\n")
    loader = CredentialLoader(env_path)
    assert os.environ.get("OPENAI_API_BASE") == _SAVED_BASE_URL

    assert loader.persist_field(provider_ids.OPENAI, CredentialField.API_BASE, None) is EnvPersistAction.REMOVED

    assert "OPENAI_API_BASE" not in os.environ
    credentials = loader.get_credentials(provider_ids.OPENAI)
    assert credentials is not None
    assert credentials.api_base is None


def test_second_loader_clearing_restores_os_value_not_first_loader_injection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two loaders on one file (startup and the dialog) still restore the true OS-level value.

    Startup builds its own loader and the Provider Settings dialog uses the
    global one; both inject the saved value, so the second must not mistake the
    first loader's injection for the operating-system value.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setenv("OPENAI_API_BASE", _OS_BASE_URL)
    env_path = _write_env(tmp_path, f"OPENAI_API_KEY={_OPENAI_KEY}\nOPENAI_API_BASE={_SAVED_BASE_URL}\n")
    startup_loader = CredentialLoader(env_path)
    dialog_loader = CredentialLoader(env_path)
    assert startup_loader.get_field(provider_ids.OPENAI, CredentialField.API_BASE) == _SAVED_BASE_URL

    assert dialog_loader.persist_field(provider_ids.OPENAI, CredentialField.API_BASE, "") is EnvPersistAction.REMOVED

    assert os.environ["OPENAI_API_BASE"] == _OS_BASE_URL


def test_reload_restores_os_value_for_variable_deleted_from_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reloading after a variable is deleted from ``.env`` by hand stops applying the deleted value.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setenv("OPENAI_API_BASE", _OS_BASE_URL)
    env_path = _write_env(tmp_path, f"OPENAI_API_KEY={_OPENAI_KEY}\nOPENAI_API_BASE={_SAVED_BASE_URL}\n")
    loader = CredentialLoader(env_path)
    assert os.environ["OPENAI_API_BASE"] == _SAVED_BASE_URL

    _ = env_path.write_text(f"OPENAI_API_KEY={_OPENAI_KEY}\n", encoding="utf-8")
    loader.reload()

    assert os.environ["OPENAI_API_BASE"] == _OS_BASE_URL
    assert loader.get_field(provider_ids.OPENAI, CredentialField.API_BASE) == _OS_BASE_URL


def test_clearing_api_key_removes_owned_alias_but_not_another_providers_key(tmp_path: Path) -> None:
    """Clearing a key removes the provider's own alias, never a variable another provider owns.

    Google owns ``GEMINI_API_KEY``; Local Transformers merely reads
    HuggingFace's ``HUGGINGFACE_API_TOKEN`` as a fallback.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = _write_env(
        tmp_path,
        (
            f"GOOGLE_API_KEY={_GOOGLE_KEY}\n"
            f"GEMINI_API_KEY={_GEMINI_ALIAS_KEY}\n"
            f"HUGGINGFACE_API_TOKEN={_HF_TOKEN}\n"
            f"LOCAL_TRANSFORMERS_HF_TOKEN={_LOCAL_TRANSFORMERS_TOKEN}\n"
        ),
    )
    loader = CredentialLoader(env_path)

    assert loader.persist_field(provider_ids.GOOGLE, CredentialField.API_KEY, "") is EnvPersistAction.REMOVED
    assert loader.persist_field(provider_ids.LOCAL_TRANSFORMERS, CredentialField.API_KEY, "") is EnvPersistAction.REMOVED

    assert CredentialLoader(env_path).get_field(provider_ids.GOOGLE, CredentialField.API_KEY) is None
    text = env_path.read_text(encoding="utf-8")
    assert "GOOGLE_API_KEY" not in text
    assert "GEMINI_API_KEY" not in text
    assert "LOCAL_TRANSFORMERS_HF_TOKEN" not in text
    assert f"HUGGINGFACE_API_TOKEN={_HF_TOKEN}" in text
    assert CredentialLoader(env_path).get_field(provider_ids.HUGGINGFACE, CredentialField.API_KEY) == _HF_TOKEN


def test_default_ollama_host_is_not_kept_as_an_override(tmp_path: Path) -> None:
    """Setting the Ollama host back to the default endpoint removes the saved override.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = _write_env(tmp_path, "OLLAMA_HOST=http://192.168.50.7:11434\n")
    loader = CredentialLoader(env_path)

    action = loader.persist_field(provider_ids.OLLAMA, CredentialField.API_BASE, "http://localhost:11434/")

    assert action is EnvPersistAction.REMOVED
    assert "OLLAMA_HOST" not in env_path.read_text(encoding="utf-8")
    keyless = CredentialLoader(env_path).get_connect_credentials(provider_ids.OLLAMA, api_key_optional=True)
    assert keyless is not None
    assert keyless.api_base is None


def test_persist_field_rejects_a_field_the_provider_does_not_store(tmp_path: Path) -> None:
    """Persisting a field with no backing variable is a programming error, not a silent no-op.

    Args:
        tmp_path: Per-test temporary directory.
    """
    loader = CredentialLoader(_write_env(tmp_path, ""))

    with pytest.raises(ValueError, match="organization_id"):
        _ = loader.persist_field(provider_ids.ANTHROPIC, CredentialField.ORGANIZATION_ID, "org-x")


def test_global_loader_reads_the_state_root_env_file_startup_uses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """On an installed build the dialog's loader and startup resolve the same ``.env``.

    The working directory holds a decoy ``.env``; the launcher-provided state
    root holds the real one. Startup reads ``get_env_file()``, so the global
    loader the Provider Settings dialog saves through must too.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    working_dir = tmp_path / "working-directory"
    working_dir.mkdir()
    _ = (working_dir / ".env").write_text(f"OPENAI_API_KEY=sk-{'d' * 48}\n", encoding="utf-8")
    monkeypatch.chdir(working_dir)

    with redirected_state_root(monkeypatch, tmp_path) as state_root:
        state_env = state_root / ".env"
        _ = state_env.write_text(f"OPENAI_API_KEY={_OPENAI_KEY}\n", encoding="utf-8")
        assert get_env_file() == state_env

        loader = get_credential_loader()

        assert loader.env_path == state_env
        credentials = loader.get_credentials(provider_ids.OPENAI)
        assert credentials is not None
        assert credentials.api_key == _OPENAI_KEY
