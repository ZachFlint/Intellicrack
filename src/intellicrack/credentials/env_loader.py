# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Credential management for Intellicrack.

This module handles loading and validating API credentials from .env files for various LLM providers.
"""

from __future__ import annotations

import functools
import os
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Final

from intellicrack.core.config import get_env_file, get_project_root
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials
from intellicrack.providers import ids as provider_ids


_logger = get_logger(__name__)


class CredentialField(StrEnum):
    """Provider credential fields that are persisted as ``.env`` variables.

    Attributes:
        API_KEY: The provider API key or access token.
        API_BASE: A custom API base URL or host override.
        ORGANIZATION_ID: The provider organization identifier.
        PROJECT_ID: The provider project identifier.
    """

    API_KEY = "api_key"
    API_BASE = "api_base"
    ORGANIZATION_ID = "organization_id"
    PROJECT_ID = "project_id"


class EnvPersistAction(StrEnum):
    """Outcome of persisting a credential field to the ``.env`` file.

    Attributes:
        WRITTEN: The variable was written to the ``.env`` file.
        REMOVED: A saved value was removed from the ``.env`` file.
        UNCHANGED: The effective value already matched, so nothing was written.
    """

    WRITTEN = "written"
    REMOVED = "removed"
    UNCHANGED = "unchanged"


@dataclass(frozen=True)
class _OverlayRecord:
    """Pre-override state of one process environment variable.

    Attributes:
        original: The value the process environment held before a ``.env``
            override was applied, or ``None`` when the variable was unset.
        injected: The value the overlay most recently wrote into the process
            environment.
    """

    original: str | None
    injected: str


class _EnvironmentOverlay:
    """Tracks process-environment variables overridden by ``.env`` entries.

    :class:`CredentialLoader` copies parsed ``.env`` entries into ``os.environ`` so provider SDKs that read their own variables observe the
    same values. When a saved entry is later removed from ``.env``, the variable must fall back to whatever the operating-system environment
    supplied before the override, rather than keep the removed value or disappear. The overlay records that pre-override value the first
    time a variable is overridden, and re-bases the record whenever the environment no longer holds the value the overlay last injected, so
    an out-of-band change is never undone. Records are process-wide because several loader instances can override the same variable.
    """

    def __init__(self) -> None:
        """Initialize an empty overlay."""
        self._records: dict[str, _OverlayRecord] = {}
        self._lock = threading.Lock()

    def apply(self, name: str, value: str) -> None:
        """Override a process environment variable with a ``.env`` value.

        Args:
            name: Environment variable name.
            value: Value to write into ``os.environ``.
        """
        with self._lock:
            current = os.environ.get(name)
            record = self._records.get(name)
            original = record.original if record is not None and current == record.injected else current
            self._records[name] = _OverlayRecord(original=original, injected=value)
            os.environ[name] = value

    def revert(self, name: str) -> None:
        """Restore a variable to its value from before any ``.env`` override.

        Variables that were never overridden, or that were changed by other
        code after the last override, are left untouched.

        Args:
            name: Environment variable name.
        """
        with self._lock:
            record = self._records.pop(name, None)
            if record is None or os.environ.get(name) != record.injected:
                return
            if record.original is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = record.original


_ENVIRONMENT_OVERLAY: Final[_EnvironmentOverlay] = _EnvironmentOverlay()


_ENV_LINE_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:export\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)"
    r"\s*=\s*"
    r"(.*)$",
)

_SAFE_VALUE_PATTERN: re.Pattern[str] = re.compile(r"^[A-Za-z0-9._/\-]+$")


def _decode_double_quoted(value: str) -> str:
    r"""Decode escape sequences inside a double-quoted .env value.

    Supports backslash-escapes for ``\\``, ``"``, ``$``, ``n``, ``r``, and
    ``t``. Unknown escapes are preserved as the escaped character (dropping
    the leading backslash) to mirror common dotenv parser behavior.

    Args:
        value: The raw string content between the surrounding double quotes.

    Returns:
        str: The decoded value with escape sequences resolved.
    """
    result: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        char = value[index]
        if char == "\\" and index + 1 < length:
            nxt = value[index + 1]
            if nxt == "n":
                result.append("\n")
            elif nxt == "r":
                result.append("\r")
            elif nxt == "t":
                result.append("\t")
            elif nxt == "\\":
                result.append("\\")
            elif nxt == '"':
                result.append('"')
            elif nxt == "$":
                result.append("$")
            else:
                result.append(nxt)
            index += 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _strip_unquoted_inline_comment(value: str) -> str:
    """Remove an inline ``#`` comment from an unquoted .env value.

    A ``#`` starts a comment only when it is preceded by whitespace or is at
    the start of the value. This mirrors typical dotenv semantics and avoids
    corrupting values that legitimately contain ``#`` (for example URLs with
    fragments, which callers should quote, but we still handle the unquoted
    case conservatively).

    Args:
        value: The unquoted value text following the ``=`` sign.

    Returns:
        str: The value with any trailing inline comment removed.
    """
    length = len(value)
    return next(
        (value[:i] for i in range(length) if value[i] == "#" and (i == 0 or value[i - 1] in {" ", "\t"})),
        value,
    )


def _parse_env_value(raw: str) -> str:
    """Parse the right-hand side of a ``KEY=VALUE`` .env entry.

    Handles double-quoted, single-quoted, and unquoted values. Double-quoted
    values have their escape sequences decoded; single-quoted values are
    treated as literal; unquoted values are trimmed and have inline comments
    stripped.

    Args:
        raw: The raw text following the ``=`` sign, before any trailing
            newline characters.

    Returns:
        str: The decoded value string.
    """
    stripped = raw.strip()
    if not stripped:
        return ""

    if stripped.startswith('"'):
        end = len(stripped) - 1
        while end > 0 and stripped[end] != '"':
            end -= 1
        if end > 0:
            inner = stripped[1:end]
            return _decode_double_quoted(inner)
        return _decode_double_quoted(stripped[1:])

    if stripped.startswith("'"):
        end = len(stripped) - 1
        while end > 0 and stripped[end] != "'":
            end -= 1
        return stripped[1:end] if end > 0 else stripped[1:]
    cleaned = _strip_unquoted_inline_comment(stripped)
    return cleaned.rstrip()


def _parse_env_text(text: str) -> dict[str, str]:
    r"""Parse .env file content into a ``dict`` of key to value.

    Accepts both ``\n`` and ``\r\n`` line endings. Blank lines and comment
    lines starting with ``#`` are ignored.

    Args:
        text: The raw .env file content.

    Returns:
        dict[str, str]: Mapping of variable names to their parsed values.
    """
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        match = _ENV_LINE_PATTERN.match(stripped_line)
        if not match:
            continue
        key = match[1]
        raw_value = match[2]
        result[key] = _parse_env_value(raw_value)
    return result


def _quote_env_value(value: str) -> str:
    r"""Serialize a value into its .env representation with minimal quoting.

    Rules:
        * Empty string becomes ``""`` (no quotes, bare ``=``).
        * Value made only of ASCII alphanumerics plus ``.``, ``_``, ``/``,
          and ``-`` is emitted unquoted.
        * Any other value is wrapped in double quotes with these escape
          sequences applied in order: ``\\`` becomes ``\\\\``, ``"`` becomes
          ``\"``, ``$`` becomes ``\$``, literal newline becomes ``\n``,
          carriage return becomes ``\r``, and tab becomes ``\t``.

    Args:
        value: The value to serialize.

    Returns:
        str: The .env-safe textual representation (without the ``KEY=``
            prefix and without a trailing newline).
    """
    if not value:
        return ""
    if _SAFE_VALUE_PATTERN.match(value):
        return value
    escaped = (
        value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _detect_eol(text: str) -> str:
    r"""Detect the dominant end-of-line marker in a text blob.

    Args:
        text: The text to examine.

    Returns:
        str: ``"\r\n"`` if CRLF line endings appear anywhere, otherwise
            ``"\n"``.
    """
    return "\r\n" if "\r\n" in text else "\n"


def _variable_line_pattern(name: str) -> re.Pattern[str]:
    """Build a pattern matching a stripped ``.env`` line that assigns ``name``.

    Args:
        name: The environment variable name.

    Returns:
        re.Pattern[str]: Pattern matching ``NAME=...`` and ``export NAME=...``.
    """
    return re.compile(rf"^(?:export\s+)?{re.escape(name)}\s*=.*$")


def _split_env_lines(text: str) -> list[tuple[str, str]]:
    r"""Split ``.env`` text into ``(content, line_ending)`` pairs.

    Only ``\r\n``, ``\n`` and ``\r`` are treated as line endings; any other
    separator ``str.splitlines`` recognises stays inside the content so the
    original bytes are reproduced exactly when the pairs are re-joined.

    Args:
        text: Raw ``.env`` file content.

    Returns:
        list[tuple[str, str]]: One ``(content, line_ending)`` pair per line;
        the final line's ending is empty when the text has no trailing newline.
    """
    pairs: list[tuple[str, str]] = []
    for raw_line in text.splitlines(keepends=True):
        if raw_line.endswith("\r\n"):
            pairs.append((raw_line[:-2], "\r\n"))
        elif raw_line.endswith(("\n", "\r")):
            pairs.append((raw_line[:-1], raw_line[-1]))
        else:
            pairs.append((raw_line, ""))
    return pairs


def _same_endpoint(first: str, second: str) -> bool:
    """Compare two endpoint URLs ignoring surrounding whitespace and trailing slashes.

    Args:
        first: First endpoint URL.
        second: Second endpoint URL.

    Returns:
        bool: True when both URLs denote the same endpoint.
    """
    return first.strip().rstrip("/") == second.strip().rstrip("/")


@dataclass
class ProviderCredentialMapping:
    """Mapping of environment variable names for a provider.

    Attributes:
        api_key_var: Environment variable name for the primary API key.
        api_base_var: Environment variable name for custom API base URL.
        organization_var: Environment variable name for organization ID.
        project_var: Environment variable name for project ID.
        api_key_aliases: Alternative environment variable names for the API key.
        default_api_base: Endpoint the provider uses when no base URL is saved.
            A saved base URL equal to it is not an override and is never
            persisted.
    """

    api_key_var: str
    api_base_var: str | None = None
    organization_var: str | None = None
    project_var: str | None = None
    api_key_aliases: tuple[str, ...] = ()
    default_api_base: str | None = None

    def env_var_for(self, field: CredentialField) -> str | None:
        """Return the primary environment variable backing a credential field.

        Args:
            field: The credential field.

        Returns:
            str | None: The variable name, or ``None`` when the provider has no
            variable for ``field``.
        """
        variables: dict[CredentialField, str | None] = {
            CredentialField.API_KEY: self.api_key_var,
            CredentialField.API_BASE: self.api_base_var,
            CredentialField.ORGANIZATION_ID: self.organization_var,
            CredentialField.PROJECT_ID: self.project_var,
        }
        return variables[field]


def _find_env_file() -> Path:
    """Find the .env file by searching up the directory tree.

    Returns:
        Path: Path to the found .env file or default location.
    """
    project_root = get_project_root()
    search_paths = [
        Path.cwd() / ".env",
        project_root / ".env",
        Path.home() / ".env",
    ]

    _logger.debug(
        "env_file_search",
        paths_checked=[str(p) for p in search_paths],
    )

    for path in search_paths:
        if path.exists():
            _logger.info("env_file_found", path=str(path))
            return path

    default_path = project_root / ".env"
    _logger.debug("env_file_not_found", default_path=str(default_path))
    return default_path


_MIN_PRINTABLE_ORD: Final[int] = 0x20
"""Lowest code point an HTTP header value may carry."""


def validate_key_format(provider: str, api_key: str) -> str | None:
    """Validate an API key's shape without assuming whose key it is.

    The previous rule rejected any key that did not start with the prefix the
    built-in provider of that name uses. That was wrong the moment a provider
    id could name any endpoint at all: a corporate gateway in front of
    Anthropic issues its own keys, an Azure deployment issues its own, and a
    LiteLLM proxy issues whatever its operator configured. Rejecting those
    made the endpoint unusable for a cosmetic reason.

    What remains are the two shapes no endpoint accepts: a key that is empty
    once trimmed, and one carrying whitespace or control characters, which
    cannot survive an HTTP header intact.

    Args:
        provider: The provider instance the key is for, used for log records.
        api_key: The API key to validate.

    Returns:
        str | None: Error message if unusable, None if valid.
    """
    if not api_key.strip():
        return "API key is empty"
    if any(character.isspace() for character in api_key) or any(ord(character) < _MIN_PRINTABLE_ORD for character in api_key):
        _logger.warning("credential_key_contains_whitespace", provider=provider)
        return "API key contains whitespace or control characters, which cannot be sent in an HTTP header"
    return None


def derived_credential_mapping(provider: str) -> ProviderCredentialMapping:
    """Derive the environment variables an unregistered instance reads.

    A user-defined instance has no entry in :data:`CredentialLoader.PROVIDER_MAPPINGS`,
    so its variables are derived from its id the way Zed derives them:
    ``<PROVIDER_ID>_API_KEY`` upper-snake, with matching names for the
    endpoint fields.

    Args:
        provider: The instance id.

    Returns:
        ProviderCredentialMapping: The derived variable mapping.
    """
    prefix = provider_ids.env_var_prefix(provider)
    return ProviderCredentialMapping(
        api_key_var=f"{prefix}_API_KEY",
        api_base_var=f"{prefix}_API_BASE",
        organization_var=f"{prefix}_ORGANIZATION",
        project_var=f"{prefix}_PROJECT",
    )


class CredentialLoader:
    """Loads and manages API credentials from .env file.

    This class parses .env files and provides credentials for each
    supported LLM provider.

    Attributes:
        PROVIDER_MAPPINGS: Mapping of provider names to their credential environment variable configuration.
    """

    PROVIDER_MAPPINGS: ClassVar[dict[str, ProviderCredentialMapping]] = {
        provider_ids.ANTHROPIC: ProviderCredentialMapping(
            api_key_var="ANTHROPIC_API_KEY",
        ),
        provider_ids.OPENAI: ProviderCredentialMapping(
            api_key_var="OPENAI_API_KEY",
            api_base_var="OPENAI_API_BASE",
            organization_var="OPENAI_ORGANIZATION",
            project_var="OPENAI_PROJECT",
        ),
        provider_ids.GOOGLE: ProviderCredentialMapping(
            api_key_var="GOOGLE_API_KEY",
            project_var="GOOGLE_CLOUD_PROJECT",
            api_key_aliases=("GEMINI_API_KEY",),
        ),
        provider_ids.OLLAMA: ProviderCredentialMapping(
            api_key_var="OLLAMA_API_KEY",
            api_base_var="OLLAMA_HOST",
            default_api_base="http://localhost:11434",
        ),
        provider_ids.OPENROUTER: ProviderCredentialMapping(
            api_key_var="OPENROUTER_API_KEY",
            api_base_var="OPENROUTER_API_BASE",
        ),
        provider_ids.HUGGINGFACE: ProviderCredentialMapping(
            api_key_var="HUGGINGFACE_API_TOKEN",
            api_base_var="HUGGINGFACE_API_BASE",
        ),
        provider_ids.GROK: ProviderCredentialMapping(
            api_key_var="XAI_API_KEY",
            api_base_var="XAI_API_BASE",
        ),
        provider_ids.LOCAL_TRANSFORMERS: ProviderCredentialMapping(
            api_key_var="LOCAL_TRANSFORMERS_HF_TOKEN",
            api_base_var="LOCAL_TRANSFORMERS_CACHE_DIR",
            api_key_aliases=("HUGGINGFACE_API_TOKEN",),
        ),
    }

    @classmethod
    def mapping_for(cls, provider: str) -> ProviderCredentialMapping:
        """Return the environment-variable mapping one instance reads.

        A built-in provider keeps its historical variable names, so ``.env``
        files stay byte-compatible. Every other instance id derives its
        variables from itself, which is what lets a user-defined endpoint be
        configured from ``.env`` at all.

        Args:
            provider: The provider instance id.

        Returns:
            ProviderCredentialMapping: The instance's variable mapping.
        """
        mapping = cls.PROVIDER_MAPPINGS.get(provider)
        return mapping if mapping is not None else derived_credential_mapping(provider)

    def __init__(self, env_path: Path | None = None) -> None:
        """Initialize the CredentialLoader with the given env file path.

        Args:
            env_path: Path to the .env file. If None, searches standard locations.
        """
        if env_path is None:
            env_path = _find_env_file()
        self.env_path = env_path
        self._env_vars: dict[str, str] = {}
        self._load_env_file()
        _logger.debug(
            "credential_loader_initialized",
            env_path=str(self.env_path),
            variable_count=len(self._env_vars),
        )

    def _load_env_file(self) -> None:
        """Load environment variables from .env file.

        Parses the .env file and loads variables into the internal dict. Also sets them in os.environ for compatibility with other
        libraries.
        """
        if not self.env_path.exists():
            _logger.debug(
                "env_file_missing",
                path=str(self.env_path),
            )
            return

        try:
            text = self.env_path.read_text(encoding="utf-8")
        except OSError:
            _logger.exception("env_file_read_failed", path=str(self.env_path))
            return

        try:
            parsed = _parse_env_text(text)
        except (ValueError, KeyError):
            _logger.exception("env_file_parse_failed", path=str(self.env_path))
            return

        for key, value in parsed.items():
            self._env_vars[key] = value
            _ENVIRONMENT_OVERLAY.apply(key, value)

        _logger.info(
            "env_variables_loaded",
            path=str(self.env_path),
            count=len(parsed),
        )

    def reload(self) -> None:
        """Reload credentials from the .env file.

        Call this method to pick up changes to the .env file without restarting the application. Variables that were removed from the file
        since the last load fall back to the value the operating-system environment supplied before the file overrode them.
        """
        _logger.debug("env_file_reloading", path=str(self.env_path))
        previous_names = set(self._env_vars)
        self._env_vars.clear()
        self._load_env_file()
        for name in previous_names.difference(self._env_vars):
            _ENVIRONMENT_OVERLAY.revert(name)
        _logger.info("env_file_reloaded", path=str(self.env_path))

    def get_credentials(self, provider: str) -> ProviderCredentials | None:
        """Get credentials for a specific provider.

        Args:
            provider: The LLM provider to get credentials for.

        Returns:
            ProviderCredentials | None: ProviderCredentials if found and valid, None otherwise.
        """
        mapping = self.mapping_for(provider)
        api_key = self._resolve_api_key(provider, mapping)
        if api_key is None:
            _logger.debug(
                "credential_not_found",
                provider=provider,
            )
            return None

        credentials = self._build_credentials(mapping, api_key)
        _logger.debug(
            "credential_retrieved",
            provider=provider,
            has_api_base=credentials.api_base is not None,
            has_organization_id=credentials.organization_id is not None,
            has_project_id=credentials.project_id is not None,
        )
        return credentials

    def get_connect_credentials(self, provider: str, *, api_key_optional: bool) -> ProviderCredentials | None:
        """Resolve the credentials a provider connects with.

        Keyed providers resolve exactly like :meth:`get_credentials`. Providers
        that can connect without an API key still receive their saved endpoint
        settings -- for example a custom ``OLLAMA_HOST`` -- when no key is
        configured, instead of an empty credential set that would silently
        discard them.

        Args:
            provider: The provider to resolve credentials for.
            api_key_optional: Whether the provider can connect without an API key.

        Returns:
            ProviderCredentials | None: The resolved credentials, or ``None`` when
            a required API key is missing or the provider is unknown.
        """
        credentials = self.get_credentials(provider)
        if credentials is not None or not api_key_optional:
            return credentials
        return self._build_credentials(self.mapping_for(provider), None)

    def env_var_for(self, provider: str, field: CredentialField) -> str | None:
        """Return the environment variable that stores a provider credential field.

        Args:
            provider: The provider.
            field: The credential field.

        Returns:
            str | None: The variable name, or ``None`` when the provider has no
            variable for ``field``.
        """
        return self.mapping_for(provider).env_var_for(field)

    def get_field(self, provider: str, field: CredentialField) -> str | None:
        """Return the effective value of a provider credential field.

        The ``.env`` file takes precedence over the process environment, the
        API key also honours the provider's alias variables, and empty values
        resolve to ``None``.

        Args:
            provider: The provider.
            field: The credential field.

        Returns:
            str | None: The effective value, or ``None`` when unset.
        """
        mapping = self.mapping_for(provider)
        if field is CredentialField.API_KEY:
            return self._resolve_api_key(provider, mapping)
        return self._optional_var(mapping.env_var_for(field))

    def get_saved_var(self, name: str) -> str | None:
        """Return a variable's value as held by this loader's ``.env`` state.

        Unlike :meth:`get_env_var`, the process environment is ignored, so the
        result reflects only values loaded from or saved to the ``.env`` file.

        Args:
            name: The environment variable name.

        Returns:
            str | None: The saved non-empty value, or ``None``.
        """
        return self._env_vars.get(name) or None

    def persist_field(self, provider: str, field: CredentialField, value: str | None) -> EnvPersistAction:
        """Persist a provider credential field to the ``.env`` file.

        A non-empty value is written only when it differs from the effective
        value, so a value inherited from the operating-system environment is
        never copied into the file unchanged. An empty value -- or, for a base
        URL, the provider's default endpoint -- clears the saved override: the
        variable (and, for an API key, its provider-owned aliases) is removed
        from the file and any value set outside the application applies again.

        Args:
            provider: The provider whose field is persisted.
            field: The credential field.
            value: The value entered by the user; ``None`` or blank clears it.

        Returns:
            EnvPersistAction: Whether the file was written, a saved value was
            removed, or nothing changed.

        Raises:
            ValueError: If the provider has no environment variable for ``field``.
        """
        mapping = self.mapping_for(provider)
        env_var = mapping.env_var_for(field)
        if env_var is None:
            msg = f"Provider {provider!r} has no environment variable for {field.value!r}"
            raise ValueError(msg)

        normalized = (value or "").strip()
        if field is CredentialField.API_BASE and mapping.default_api_base and _same_endpoint(normalized, mapping.default_api_base):
            normalized = ""

        if not normalized:
            removed = [name for name in self._clearable_variables(mapping, field) if self.remove_from_env_file(name)]
            return EnvPersistAction.REMOVED if removed else EnvPersistAction.UNCHANGED

        if normalized == self.get_field(provider, field):
            return EnvPersistAction.UNCHANGED

        self.save_to_env_file(env_var, normalized)
        return EnvPersistAction.WRITTEN

    @classmethod
    def _clearable_variables(cls, mapping: ProviderCredentialMapping, field: CredentialField) -> tuple[str, ...]:
        """Return the variables removed when a credential field is cleared.

        Clearing an API key also removes the provider's alias variables,
        except an alias that is another provider's primary key variable, which
        that provider still owns.

        Args:
            mapping: The provider's credential variable mapping.
            field: The credential field being cleared.

        Returns:
            tuple[str, ...]: Variable names to remove, primary variable first.
        """
        primary = mapping.env_var_for(field)
        if primary is None:
            return ()
        if field is not CredentialField.API_KEY:
            return (primary,)
        foreign_primaries = {other.api_key_var for other in cls.PROVIDER_MAPPINGS.values() if other is not mapping}
        return (primary, *(alias for alias in mapping.api_key_aliases if alias not in foreign_primaries))

    def _resolve_api_key(self, provider: str, mapping: ProviderCredentialMapping) -> str | None:
        """Resolve a provider API key from its primary variable, then its aliases.

        Args:
            provider: Provider whose key is resolved, used for log records.
            mapping: The provider's credential variable mapping.

        Returns:
            str | None: The first non-empty key found, or ``None``.
        """
        if api_key := self._get_var(mapping.api_key_var):
            return api_key
        for alias in mapping.api_key_aliases:
            if api_key := self._get_var(alias):
                _logger.debug(
                    "credential_found_via_alias",
                    provider=provider,
                    alias=alias,
                )
                return api_key
        return None

    def _build_credentials(self, mapping: ProviderCredentialMapping, api_key: str | None) -> ProviderCredentials:
        """Assemble credentials from a key and the provider's endpoint variables.

        Args:
            mapping: The provider's credential variable mapping.
            api_key: The resolved API key, or ``None`` for a keyless connection.

        Returns:
            ProviderCredentials: Credentials carrying the key and every saved
            endpoint setting.
        """
        return ProviderCredentials(
            api_key=api_key,
            api_base=self._optional_var(mapping.api_base_var),
            organization_id=self._optional_var(mapping.organization_var),
            project_id=self._optional_var(mapping.project_var),
        )

    def _optional_var(self, name: str | None) -> str | None:
        """Resolve an optional variable name to its value.

        Args:
            name: Environment variable name, or ``None`` when the provider has
                no such variable.

        Returns:
            str | None: The variable value, or ``None`` when unnamed or unset.
        """
        return self._get_var(name) if name else None

    def _get_var(self, name: str) -> str | None:
        """Get an environment variable value.

        First checks the parsed .env file, then falls back to os.environ. Empty values resolve to ``None``.

        Args:
            name: Environment variable name.

        Returns:
            str | None: Variable value or None if not found.
        """
        if value := self._env_vars.get(name):
            return value
        return os.environ.get(name) or None

    def validate_credentials(self, provider: str) -> tuple[bool, str | None]:
        """Validate that credentials exist and are properly formatted.

        Args:
            provider: The provider to validate credentials for.

        Returns:
            tuple[bool, str | None]: Tuple of (is_valid, error_message). error_message is None if valid.
        """
        mapping = self.mapping_for(provider)
        api_key = self._resolve_api_key(provider, mapping)
        if not api_key:
            _logger.debug(
                "credential_validation_failed",
                provider=provider,
                reason="missing_key",
            )
            return False, f"Missing {mapping.api_key_var}"

        validation_result = validate_key_format(provider, api_key)
        if validation_result is not None:
            _logger.warning(
                "credential_validation_failed",
                provider=provider,
                reason="invalid_format",
            )
            return False, validation_result

        _logger.debug(
            "credential_validated",
            provider=provider,
            valid=True,
        )
        return True, None

    def list_configured_providers(self) -> list[str]:
        """List all providers that have credentials configured.

        Returns:
            list[str]: List of provider names with valid credentials.
        """
        configured: list[str] = []
        for provider in provider_ids.BUILTIN_PROVIDER_IDS:
            is_valid, _ = self.validate_credentials(provider)
            if is_valid:
                configured.append(provider)
        _logger.debug(
            "configured_providers_listed",
            count=len(configured),
            providers=list(configured),
        )
        return configured

    def list_missing_providers(self) -> list[str]:
        """List all providers that are missing credentials.

        Returns:
            list[str]: List of provider names without valid credentials.
        """
        missing: list[str] = []
        for provider in provider_ids.BUILTIN_PROVIDER_IDS:
            is_valid, _ = self.validate_credentials(provider)
            if not is_valid:
                missing.append(provider)
        _logger.debug(
            "missing_providers_listed",
            count=len(missing),
            providers=list(missing),
        )
        return missing

    def set_env_var(self, name: str, value: str) -> None:
        """Set an environment variable (in memory only).

        Args:
            name: The environment variable name.
            value: The value to set.
        """
        self._env_vars[name] = value
        _ENVIRONMENT_OVERLAY.apply(name, value)

    def get_env_var(self, name: str, default: str | None = None) -> str | None:
        """Get an environment variable value.

        Checks the internal cache first, then falls back to os.environ.

        Args:
            name: The environment variable name.
            default: Default value if the variable is not found.

        Returns:
            str | None: The variable value, or default if not found.
        """
        value = self._env_vars.get(name)
        return value if value is not None else os.environ.get(name, default)

    def save_to_env_file(self, name: str, value: str) -> None:
        r"""Save an environment variable to the .env file.

        Updates an existing variable or adds a new one at the end of the file.
        Preserves comments and file structure, and preserves the existing
        end-of-line style. Uses ``\n`` for newly created files. Values are
        quoted and escaped per :func:`_quote_env_value` rules to guarantee a
        lossless round-trip with the parser. An ``OSError`` raised while
        reading or writing the file propagates to the caller.

        Args:
            name: The environment variable name.
            value: The value to save.
        """
        self.set_env_var(name, value)
        _logger.info("env_file_write_started", path=str(self.env_path), variable=name)

        new_line_body = f"{name}={_quote_env_value(value)}"
        key_pattern = _variable_line_pattern(name)
        existing_text = self._read_env_file_text()
        eol = _detect_eol(existing_text) if existing_text else "\n"

        lines: list[str] = []
        key_found = False
        for content, line_eol in _split_env_lines(existing_text):
            if key_pattern.match(content.strip()):
                lines.append(f"{new_line_body}{line_eol or eol}")
                key_found = True
            else:
                lines.append(f"{content}{line_eol}")

        if not key_found:
            if lines and not lines[-1].endswith(("\n", "\r")):
                lines[-1] = f"{lines[-1]}{eol}"
            lines.append(f"{new_line_body}{eol}")

        self._write_env_file_lines(lines)

        _logger.info(
            "env_file_saved",
            path=str(self.env_path),
            variable=name,
            updated_existing=key_found,
        )

    def remove_from_env_file(self, name: str) -> bool:
        """Remove a variable from the ``.env`` file and from this loader.

        Every line assigning ``name`` (including ``export`` forms) is deleted
        while comments, other variables and the file's end-of-line style are
        preserved. The process environment falls back to the value the
        operating system supplied before the file overrode it, so a variable
        set outside the application still applies. An ``OSError`` raised while
        reading or writing the file propagates to the caller, leaving the
        loader's in-memory state unchanged.

        Args:
            name: The environment variable name.

        Returns:
            bool: True when a saved value was removed from the file or from
            this loader's in-memory state.
        """
        key_pattern = _variable_line_pattern(name)
        kept_lines: list[str] = []
        removed_lines = 0
        for content, line_eol in _split_env_lines(self._read_env_file_text()):
            if key_pattern.match(content.strip()):
                removed_lines += 1
            else:
                kept_lines.append(f"{content}{line_eol}")

        if removed_lines:
            self._write_env_file_lines(kept_lines)

        had_saved_value = self._env_vars.pop(name, None) is not None
        _ENVIRONMENT_OVERLAY.revert(name)
        removed = removed_lines > 0 or had_saved_value
        if removed:
            _logger.info(
                "env_file_variable_removed",
                path=str(self.env_path),
                variable=name,
                removed_lines=removed_lines,
            )
        return removed

    def _read_env_file_text(self) -> str:
        """Read the raw ``.env`` file content with its line endings intact.

        Returns:
            str: The file content, or an empty string when the file does not exist.

        Raises:
            OSError: If the existing file cannot be read.
        """
        if not self.env_path.exists():
            return ""
        try:
            with self.env_path.open("r", encoding="utf-8", newline="") as f:
                text = f.read()
        except OSError:
            _logger.exception("env_file_read_existing_failed", path=str(self.env_path))
            raise
        return text

    def _write_env_file_lines(self, lines: list[str]) -> None:
        """Write lines, each carrying its own line ending, to the ``.env`` file.

        Args:
            lines: The complete file content split into lines.

        Raises:
            OSError: If the file cannot be written.
        """
        self.env_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.env_path.open("w", encoding="utf-8", newline="") as f:
                f.writelines(lines)
        except OSError:
            _logger.exception("env_file_write_failed", path=str(self.env_path))
            raise


def get_api_key_env_var_mapping() -> dict[str, str]:
    """Get a mapping of provider ID to API key environment variable name.

    Derives the mapping from PROVIDER_MAPPINGS to maintain a single source
    of truth for env var names.

    Returns:
        dict[str, str]: Dict mapping provider ID string to API key env var name.
    """
    return {provider: mapping.api_key_var for provider, mapping in CredentialLoader.PROVIDER_MAPPINGS.items()}


@dataclass(frozen=True)
class _EnvTemplateVar:
    """A single environment variable entry rendered into the `.env` template.

    Attributes:
        key: Environment variable name.
        placeholder: Example/placeholder value shown in the template.
        commented: Whether the line is emitted commented-out (``# KEY=value``)
            because the variable is optional.
        suffix_comment: Optional trailing inline comment appended after the
            value (for example ``# Usually not needed for local``).
    """

    key: str
    placeholder: str
    commented: bool = False
    suffix_comment: str | None = None


@dataclass(frozen=True)
class _EnvTemplateSection:
    """A titled group of related variables in the `.env` template.

    Attributes:
        title: Section heading rendered as a comment line.
        variables: Ordered variables belonging to this section.
    """

    title: str
    variables: tuple[_EnvTemplateVar, ...]


_ENV_TEMPLATE_SECTIONS: Final[tuple[_EnvTemplateSection, ...]] = (
    _EnvTemplateSection(
        "Anthropic (Claude)",
        (_EnvTemplateVar("ANTHROPIC_API_KEY", "sk-ant-api03-..."),),
    ),
    _EnvTemplateSection(
        "OpenAI (GPT)",
        (
            _EnvTemplateVar("OPENAI_API_KEY", "sk-..."),
            _EnvTemplateVar("OPENAI_ORGANIZATION", "org-...", commented=True),
            _EnvTemplateVar("OPENAI_API_BASE", "https://api.openai.com/v1", commented=True),
        ),
    ),
    _EnvTemplateSection(
        "Google AI (Gemini)",
        (
            _EnvTemplateVar("GOOGLE_API_KEY", "..."),
            _EnvTemplateVar("GOOGLE_CLOUD_PROJECT", "your-project-id", commented=True),
        ),
    ),
    _EnvTemplateSection(
        "OpenRouter",
        (_EnvTemplateVar("OPENROUTER_API_KEY", "sk-or-v1-..."),),
    ),
    _EnvTemplateSection(
        "Ollama (local)",
        (
            _EnvTemplateVar("OLLAMA_HOST", "http://localhost:11434", commented=True),
            _EnvTemplateVar("OLLAMA_API_KEY", "", commented=True, suffix_comment="# Usually not needed for local"),
        ),
    ),
)


def _render_env_template_var(var: _EnvTemplateVar) -> str:
    """Render a single template variable as a `.env` line.

    Args:
        var: The template variable to render.

    Returns:
        str: The rendered line, without a trailing newline.
    """
    prefix = "# " if var.commented else ""
    suffix = f"  {var.suffix_comment}" if var.suffix_comment else ""
    return f"{prefix}{var.key}={var.placeholder}{suffix}"


def _render_full_env_template() -> str:
    """Render the complete `.env` template text for a brand-new file.

    Returns:
        str: The full template content, ending in a single trailing newline.
    """
    lines: list[str] = [
        "# Intellicrack API Credentials",
        "# Copy this file to .env and fill in your API keys",
        "",
    ]
    for section in _ENV_TEMPLATE_SECTIONS:
        lines.append(f"# {section.title}")
        lines.extend(_render_env_template_var(var) for var in section.variables)
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _render_missing_env_vars(existing_keys: set[str]) -> tuple[str, tuple[str, ...]]:
    """Render only the template variables absent from an existing `.env` file.

    Args:
        existing_keys: Environment variable names already defined
            (uncommented) in the existing file.

    Returns:
        tuple[str, tuple[str, ...]]: The rendered block of missing
            variables (grouped by section, each section header included
            only when it has at least one missing variable), and the
            ordered tuple of variable names that were included.
    """
    block_lines: list[str] = []
    added_keys: list[str] = []
    for section in _ENV_TEMPLATE_SECTIONS:
        section_vars = [var for var in section.variables if var.key not in existing_keys]
        if not section_vars:
            continue
        block_lines.append(f"# {section.title}")
        block_lines.extend(_render_env_template_var(var) for var in section_vars)
        block_lines.append("")
        added_keys.extend(var.key for var in section_vars)
    return "\n".join(block_lines).rstrip("\n") + "\n" if block_lines else "", tuple(added_keys)


@dataclass(frozen=True)
class EnvTemplateResult:
    """Outcome of a :func:`create_env_template` call.

    Attributes:
        path: The `.env` file that was written to or merged into.
        backup_path: Path to a timestamped backup of the file's prior
            content, or ``None`` when no pre-existing content needed
            backing up (a fresh file was created).
        created: ``True`` if ``path`` did not previously contain any
            content and was written from the full template.
        merged: ``True`` if ``path`` already contained content and was
            preserved unmodified aside from appending any missing
            template variables.
        added_keys: Names of the variables newly appended to the file.
            Keys already present in the file are never included here
            because their existing lines -- and values -- are left
            untouched.
    """

    path: Path
    backup_path: Path | None
    created: bool
    merged: bool
    added_keys: tuple[str, ...]


def create_env_template(path: Path) -> EnvTemplateResult:
    """Create or safely merge a template .env file with all supported providers.

    When ``path`` does not exist, or exists but is empty, the full template
    is written directly. When ``path`` already contains content, that
    content is never truncated or overwritten: a timestamped backup of the
    existing file is written first, and only the template variables that
    are not already defined in the file are appended to its end. Every
    existing ``KEY=value`` line -- and therefore any real credential it
    holds -- is left completely untouched.

    Args:
        path: Path to the `.env` file to create or merge the template into.

    Returns:
        EnvTemplateResult: Details of what happened, so callers can inform
            the user whether the file was created fresh or merged, and
            where any backup was written.

    Raises:
        OSError: If the template file, or its pre-write backup, cannot be
            written.
    """
    _logger.debug("env_template_creating", path=str(path))
    path.parent.mkdir(parents=True, exist_ok=True)

    existing_text = ""
    if path.exists():
        try:
            existing_text = path.read_text(encoding="utf-8")
        except OSError:
            _logger.exception("env_template_read_existing_failed", path=str(path))
            raise

    if not existing_text.strip():
        try:
            path.write_text(_render_full_env_template(), encoding="utf-8")
        except OSError:
            _logger.exception("env_template_write_failed", path=str(path))
            raise
        all_keys = tuple(var.key for section in _ENV_TEMPLATE_SECTIONS for var in section.variables)
        _logger.info("env_template_created", path=str(path), created=True, merged=False)
        return EnvTemplateResult(path=path, backup_path=None, created=True, merged=False, added_keys=all_keys)

    existing_keys = set(_parse_env_text(existing_text).keys())

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    backup_path = path.with_name(f"{path.name}.{timestamp}.bak")
    try:
        backup_path.write_text(existing_text, encoding="utf-8")
    except OSError:
        _logger.exception("env_template_backup_failed", path=str(backup_path))
        raise
    _logger.info("env_template_backup_created", path=str(path), backup_path=str(backup_path))

    missing_block, added_keys = _render_missing_env_vars(existing_keys)
    if not added_keys:
        _logger.info("env_template_merge_noop", path=str(path), backup_path=str(backup_path))
        return EnvTemplateResult(path=path, backup_path=backup_path, created=False, merged=True, added_keys=())

    separator = "" if existing_text.endswith("\n") else "\n"
    appended = f"{separator}\n# --- Added by Intellicrack template merge on {timestamp} ---\n{missing_block}"
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(appended)
    except OSError:
        _logger.exception("env_template_append_failed", path=str(path))
        raise
    _logger.info(
        "env_template_merged",
        path=str(path),
        backup_path=str(backup_path),
        added_keys=list(added_keys),
    )
    return EnvTemplateResult(path=path, backup_path=backup_path, created=False, merged=True, added_keys=added_keys)


@functools.lru_cache(maxsize=1)
def get_credential_loader() -> CredentialLoader:
    r"""Get the global credential loader instance.

    The loader is bound to the same state-root ``.env`` file the application
    loads at startup (:func:`intellicrack.core.config.get_env_file`), so
    credentials saved through the Provider Settings dialog are the ones the
    next launch connects with. On an installed build that file lives under
    ``%LOCALAPPDATA%\Intellicrack`` rather than in the working or install
    directory.

    Returns:
        CredentialLoader: The singleton CredentialLoader instance.
    """
    return CredentialLoader(get_env_file())
