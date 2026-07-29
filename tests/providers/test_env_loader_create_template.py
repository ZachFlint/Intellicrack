# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate: ``create_env_template`` must never destroy a real `.env`.

S16-D06 regression coverage. Historically, clicking "Create .env" in the
Providers configuration dialog called ``create_env_template`` with an
unconditional ``path.open("w")``, silently truncating any existing `.env`
and replacing it with a placeholder template. Because the keyring can be
empty, the `.env` file is sometimes the only on-disk copy of a user's real
API keys, so this was outright data loss.

These tests exercise real file I/O against a ``tmp_path`` directory (no
filesystem mocks) and assert that a populated `.env` survives a
``create_env_template`` call byte-for-byte, that a backup is produced, and
that only genuinely missing template variables get appended.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.credentials.env_loader import EnvTemplateResult, create_env_template


if TYPE_CHECKING:
    from pathlib import Path


_REAL_ENV_CONTENT = (
    "# my real secrets, do not lose these\n"
    "ANTHROPIC_API_KEY=PRESERVE-ANTHROPIC-KEY-VALUE\n"  # pragma: allowlist secret
    "OPENAI_API_KEY=PRESERVE-OPENAI-KEY-VALUE\n"  # pragma: allowlist secret
    "CUSTOM_VAR=some-custom-value\n"  # pragma: allowlist secret
)


def test_create_env_template_preserves_existing_real_keys(tmp_path: Path) -> None:
    """A populated `.env` must retain its real key values after templating.

    This is the core falsifiable regression gate for S16-D06: it fails
    immediately if the implementation reverts to an unconditional
    ``path.open("w")`` truncate, because the original key/value lines
    would no longer be present in the file.

    Args:
        tmp_path: Pytest-provided temporary directory, used for real file
            I/O with no filesystem mocking.
    """
    env_path = tmp_path / ".env"
    env_path.write_text(_REAL_ENV_CONTENT, encoding="utf-8")

    result = create_env_template(env_path)

    after_text = env_path.read_text(encoding="utf-8")
    assert "ANTHROPIC_API_KEY=PRESERVE-ANTHROPIC-KEY-VALUE" in after_text, (  # pragma: allowlist secret
        "real ANTHROPIC_API_KEY value was lost -- template call truncated the live .env"
    )
    assert "OPENAI_API_KEY=PRESERVE-OPENAI-KEY-VALUE" in after_text, (  # pragma: allowlist secret
        "real OPENAI_API_KEY value was lost -- template call truncated the live .env"
    )
    assert "CUSTOM_VAR=some-custom-value" in after_text, "unrelated custom variable was lost"  # pragma: allowlist secret
    assert result.created is False
    assert result.merged is True


def test_create_env_template_writes_timestamped_backup(tmp_path: Path) -> None:
    """A backup of the pre-existing `.env` content must be written to disk.

    Even though the implementation preserves the original file via an
    append-only merge, it still produces a timestamped backup as a second,
    independent line of defense: the test asserts the backup file exists,
    is reported back to the caller, and contains the original real values.

    Args:
        tmp_path: Pytest-provided temporary directory, used for real file
            I/O with no filesystem mocking.
    """
    env_path = tmp_path / ".env"
    env_path.write_text(_REAL_ENV_CONTENT, encoding="utf-8")

    result = create_env_template(env_path)

    assert result.backup_path is not None, "no backup was recorded for a pre-existing .env"
    assert result.backup_path.exists(), f"reported backup path {result.backup_path} does not exist on disk"
    backup_text = result.backup_path.read_text(encoding="utf-8")
    assert backup_text == _REAL_ENV_CONTENT, "backup content does not match the original .env content exactly"


def test_create_env_template_only_appends_missing_keys(tmp_path: Path) -> None:
    """Only template variables absent from the existing file are appended.

    ``ANTHROPIC_API_KEY`` and ``OPENAI_API_KEY`` are already present in the
    seed file, so they must not be listed as newly added, and the
    placeholder text for those keys (``sk-ant-api03-...`` / ``sk-...``)
    must not appear anywhere in the resulting file -- proving the merge did
    not clobber real values with template placeholders.

    Args:
        tmp_path: Pytest-provided temporary directory, used for real file
            I/O with no filesystem mocking.
    """
    env_path = tmp_path / ".env"
    env_path.write_text(_REAL_ENV_CONTENT, encoding="utf-8")

    result = create_env_template(env_path)

    assert "ANTHROPIC_API_KEY" not in result.added_keys
    assert "OPENAI_API_KEY" not in result.added_keys
    assert "GOOGLE_API_KEY" in result.added_keys
    assert "OPENROUTER_API_KEY" in result.added_keys

    after_text = env_path.read_text(encoding="utf-8")
    assert "sk-ant-api03-..." not in after_text, "placeholder overwrote the real Anthropic key"
    assert "ANTHROPIC_API_KEY=PRESERVE-ANTHROPIC-KEY-VALUE" in after_text  # pragma: allowlist secret
    assert "GOOGLE_API_KEY=..." in after_text, "missing GOOGLE_API_KEY template line was not appended"


def test_create_env_template_creates_fresh_file_when_absent(tmp_path: Path) -> None:
    """A nonexistent `.env` is created fresh from the full template.

    This exercises the non-merge branch and confirms the return type
    contract (``EnvTemplateResult``) that ``provider_config.py`` relies on
    to report outcomes to the user.

    Args:
        tmp_path: Pytest-provided temporary directory, used for real file
            I/O with no filesystem mocking.
    """
    env_path = tmp_path / ".env"
    assert not env_path.exists()

    result = create_env_template(env_path)

    assert isinstance(result, EnvTemplateResult)
    assert result.created is True
    assert result.merged is False
    assert result.backup_path is None
    assert env_path.exists()
    content = env_path.read_text(encoding="utf-8")
    assert "ANTHROPIC_API_KEY=sk-ant-api03-..." in content
    assert "OPENAI_API_KEY=sk-..." in content


def test_create_env_template_noop_when_all_keys_already_present(tmp_path: Path) -> None:
    """When every template variable is already defined, nothing is appended.

    Args:
        tmp_path: Pytest-provided temporary directory, used for real file
            I/O with no filesystem mocking.
    """
    full_seed = (
        "ANTHROPIC_API_KEY=k1\n"
        "OPENAI_API_KEY=k2\n"
        "OPENAI_ORGANIZATION=org\n"
        "OPENAI_API_BASE=https://example.invalid\n"
        "GOOGLE_API_KEY=k3\n"
        "GOOGLE_CLOUD_PROJECT=proj\n"
        "OPENROUTER_API_KEY=k4\n"
        "OLLAMA_HOST=http://localhost:11434\n"
        "OLLAMA_API_KEY=k5\n"
    )
    env_path = tmp_path / ".env"
    env_path.write_text(full_seed, encoding="utf-8")

    result = create_env_template(env_path)

    assert result.added_keys == ()
    after_text = env_path.read_text(encoding="utf-8")
    assert after_text == full_seed, "file was modified even though no keys were missing"
