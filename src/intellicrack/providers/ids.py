# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Canonical provider instance identifiers.

A provider is identified by a plain ``str`` instance id rather than a closed
enum so a user can register an arbitrary OpenAI-compatible or
Anthropic-compatible endpoint (a corporate gateway, a LiteLLM proxy, vLLM, a
second OpenAI account) without a code change.

The built-in ids exported here keep the exact string values the removed
provider enum carried, so ``providers.json``, the sessions SQLite
``provider`` column, ``.env`` variable names and the discovery cache all
round-trip byte-identically with no data migration.

Exhaustiveness checking has not been lost: it moved from provider identity
(now open) to :class:`~intellicrack.providers.dialects.base.ApiDialect`, which
remains a closed enum guarded by ``_assert_never``.
"""

from __future__ import annotations

import re
from typing import Final

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)

ANTHROPIC: Final[str] = "anthropic"
OPENAI: Final[str] = "openai"
GOOGLE: Final[str] = "google"
OLLAMA: Final[str] = "ollama"
OPENROUTER: Final[str] = "openrouter"
HUGGINGFACE: Final[str] = "huggingface"
GROK: Final[str] = "grok"
LOCAL_TRANSFORMERS: Final[str] = "local_transformers"

BUILTIN_PROVIDER_IDS: Final[tuple[str, ...]] = (
    ANTHROPIC,
    OPENAI,
    GOOGLE,
    OLLAMA,
    OPENROUTER,
    HUGGINGFACE,
    GROK,
    LOCAL_TRANSFORMERS,
)

PROVIDER_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")

MAX_PROVIDER_ID_CHARS: Final[int] = 64


class InvalidProviderIdError(ValueError):
    """Raised when a provider instance id violates the id grammar.

    Attributes:
        provider_id: The offending identifier exactly as supplied by the
            caller, before normalization.
    """

    provider_id: str

    def __init__(self, provider_id: str) -> None:
        """Initialize the error with the rejected identifier.

        Args:
            provider_id: The identifier that failed validation.
        """
        self.provider_id = provider_id
        message = (
            f"Invalid provider id {provider_id!r}: ids must match "
            f"^[a-z0-9][a-z0-9_-]{{0,{MAX_PROVIDER_ID_CHARS - 1}}}$ "
            "(lowercase letters, digits, underscore and hyphen, starting with a letter or digit)"
        )
        super().__init__(message)


def normalize_provider_id(provider_id: str) -> str:
    """Normalize and validate a provider instance id.

    Surrounding whitespace is stripped and the id is lower-cased before
    validation, so a value typed into the GUI as ``"My-Gateway "`` becomes
    ``"my-gateway"``. Case folding is what makes the removal of the old
    ``ProviderEnum(provider.lower())`` call sites behaviour-preserving.

    Args:
        provider_id: Candidate instance id.

    Returns:
        str: The normalized id.

    Raises:
        InvalidProviderIdError: When the normalized id does not match
            :data:`PROVIDER_ID_PATTERN`.
    """
    candidate = provider_id.strip().lower()
    if not candidate:
        _logger.warning("provider_id_rejected_empty")
        raise InvalidProviderIdError(provider_id)
    if PROVIDER_ID_PATTERN.fullmatch(candidate) is None:
        _logger.warning("provider_id_rejected", provider_id=provider_id)
        raise InvalidProviderIdError(provider_id)
    return candidate


def is_valid_provider_id(provider_id: str) -> bool:
    """Report whether a candidate id satisfies the provider id grammar.

    Args:
        provider_id: Candidate instance id, normalized before testing.

    Returns:
        bool: ``True`` when :func:`normalize_provider_id` would accept it.
    """
    candidate = provider_id.strip().lower()
    return bool(candidate) and PROVIDER_ID_PATTERN.fullmatch(candidate) is not None


def is_builtin_provider_id(provider_id: str) -> bool:
    """Report whether an id names one of the eight built-in providers.

    Args:
        provider_id: Instance id to test; normalized before comparison.

    Returns:
        bool: ``True`` when the id is a built-in provider id.
    """
    return provider_id.strip().lower() in BUILTIN_PROVIDER_IDS


def env_var_prefix(provider_id: str) -> str:
    """Derive the upper-snake environment-variable stem for an instance id.

    Follows Zed's rule: the ``.env`` / process-environment key for an
    instance is ``<PROVIDER_ID>_API_KEY`` with the id upper-cased and
    hyphens folded to underscores, so ``my-gateway`` reads
    ``MY_GATEWAY_API_KEY``.

    Args:
        provider_id: Instance id to derive the stem from.

    Returns:
        str: Upper-snake stem with no trailing separator.
    """
    return provider_id.strip().lower().replace("-", "_").upper()


def api_key_env_var(provider_id: str) -> str:
    """Derive the API-key environment-variable name for an instance id.

    Args:
        provider_id: Instance id to derive the variable name from.

    Returns:
        str: The ``<PROVIDER_ID>_API_KEY`` variable name.
    """
    return f"{env_var_prefix(provider_id)}_API_KEY"
