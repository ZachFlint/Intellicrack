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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Final

from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials, ProviderName


_logger = get_logger(__name__)


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


@dataclass
class ProviderCredentialMapping:
    """Mapping of environment variable names for a provider.

    Attributes:
        api_key_var: Environment variable name for the primary API key.
        api_base_var: Environment variable name for custom API base URL.
        organization_var: Environment variable name for organization ID.
        project_var: Environment variable name for project ID.
        api_key_aliases: Alternative environment variable names for the API key.
    """

    api_key_var: str
    api_base_var: str | None = None
    organization_var: str | None = None
    project_var: str | None = None
    api_key_aliases: tuple[str, ...] = ()


def _find_env_file() -> Path:
    """Find the .env file by searching up the directory tree.

    Returns:
        Path: Path to the found .env file or default location.
    """
    project_root = Path(__file__).resolve().parents[3]
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


def _validate_key_format(provider: ProviderName, api_key: str) -> str | None:
    """Validate API key format for a provider.

    Args:
        provider: The provider the key is for.
        api_key: The API key to validate.

    Returns:
        str | None: Error message if invalid, None if valid.
    """
    if provider == ProviderName.ANTHROPIC and not api_key.startswith("sk-ant-"):
        return "Anthropic API key should start with 'sk-ant-'"

    if provider == ProviderName.OPENAI and not api_key.startswith("sk-"):
        return "OpenAI API key should start with 'sk-'"

    if provider == ProviderName.OPENROUTER and not api_key.startswith("sk-or-"):
        return "OpenRouter API key should start with 'sk-or-'"

    if provider == ProviderName.HUGGINGFACE and not api_key.startswith("hf_"):
        return "HuggingFace API token should start with 'hf_'"

    if provider == ProviderName.GROK and not api_key.startswith("xai-"):
        return "Grok API key should start with 'xai-'"

    return None


class CredentialLoader:
    """Loads and manages API credentials from .env file.

    This class parses .env files and provides credentials for each
    supported LLM provider.

    Attributes:
        PROVIDER_MAPPINGS: Mapping of provider names to their credential environment variable configuration.
    """

    PROVIDER_MAPPINGS: ClassVar[dict[ProviderName, ProviderCredentialMapping]] = {
        ProviderName.ANTHROPIC: ProviderCredentialMapping(
            api_key_var="ANTHROPIC_API_KEY",
        ),
        ProviderName.OPENAI: ProviderCredentialMapping(
            api_key_var="OPENAI_API_KEY",
            api_base_var="OPENAI_API_BASE",
            organization_var="OPENAI_ORGANIZATION",
            project_var="OPENAI_PROJECT",
        ),
        ProviderName.GOOGLE: ProviderCredentialMapping(
            api_key_var="GOOGLE_API_KEY",
            project_var="GOOGLE_CLOUD_PROJECT",
            api_key_aliases=("GEMINI_API_KEY",),
        ),
        ProviderName.OLLAMA: ProviderCredentialMapping(
            api_key_var="OLLAMA_API_KEY",
            api_base_var="OLLAMA_HOST",
        ),
        ProviderName.OPENROUTER: ProviderCredentialMapping(
            api_key_var="OPENROUTER_API_KEY",
        ),
        ProviderName.HUGGINGFACE: ProviderCredentialMapping(
            api_key_var="HUGGINGFACE_API_TOKEN",
            api_base_var="HUGGINGFACE_API_BASE",
        ),
        ProviderName.GROK: ProviderCredentialMapping(
            api_key_var="XAI_API_KEY",
            api_base_var="XAI_API_BASE",
        ),
        ProviderName.LOCAL_TRANSFORMERS: ProviderCredentialMapping(
            api_key_var="LOCAL_TRANSFORMERS_HF_TOKEN",
            api_base_var="LOCAL_TRANSFORMERS_CACHE_DIR",
            api_key_aliases=("HUGGINGFACE_API_TOKEN",),
        ),
    }

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
            os.environ[key] = value

        _logger.info(
            "env_variables_loaded",
            path=str(self.env_path),
            count=len(parsed),
        )

    def reload(self) -> None:
        """Reload credentials from the .env file.

        Call this method to pick up changes to the .env file without restarting the application.
        """
        _logger.debug("env_file_reloading", path=str(self.env_path))
        self._env_vars.clear()
        self._load_env_file()
        _logger.info("env_file_reloaded", path=str(self.env_path))

    def get_credentials(self, provider: ProviderName) -> ProviderCredentials | None:
        """Get credentials for a specific provider.

        Args:
            provider: The LLM provider to get credentials for.

        Returns:
            ProviderCredentials | None: ProviderCredentials if found and valid, None otherwise.
        """
        mapping = self.PROVIDER_MAPPINGS.get(provider)
        if mapping is None:
            _logger.debug(
                "credential_provider_unknown",
                provider=provider.value,
            )
            return None

        api_key = self._get_var(mapping.api_key_var)
        if not api_key:
            for alias in mapping.api_key_aliases:
                api_key = self._get_var(alias)
                if api_key:
                    _logger.debug(
                        "credential_found_via_alias",
                        provider=provider.value,
                        alias=alias,
                    )
                    break
        if not api_key:
            _logger.debug(
                "credential_not_found",
                provider=provider.value,
            )
            return None

        api_base: str | None = None
        if mapping.api_base_var:
            api_base = self._get_var(mapping.api_base_var)

        organization_id: str | None = None
        if mapping.organization_var:
            organization_id = self._get_var(mapping.organization_var)

        project_id: str | None = None
        if mapping.project_var:
            project_id = self._get_var(mapping.project_var)

        _logger.debug(
            "credential_retrieved",
            provider=provider.value,
            has_api_base=api_base is not None,
            has_organization_id=organization_id is not None,
            has_project_id=project_id is not None,
        )

        return ProviderCredentials(
            api_key=api_key,
            api_base=api_base,
            organization_id=organization_id,
            project_id=project_id,
        )

    def _get_var(self, name: str) -> str | None:
        """Get an environment variable value.

        First checks the parsed .env file, then falls back to os.environ.

        Args:
            name: Environment variable name.

        Returns:
            str | None: Variable value or None if not found.
        """
        if value := self._env_vars.get(name):
            return value
        return os.environ.get(name)

    def validate_credentials(self, provider: ProviderName) -> tuple[bool, str | None]:
        """Validate that credentials exist and are properly formatted.

        Args:
            provider: The provider to validate credentials for.

        Returns:
            tuple[bool, str | None]: Tuple of (is_valid, error_message). error_message is None if valid.
        """
        mapping = self.PROVIDER_MAPPINGS.get(provider)
        if mapping is None:
            _logger.debug(
                "credential_validation_failed",
                provider=provider.value,
                reason="unknown_provider",
            )
            return False, f"Unknown provider: {provider.value}"

        api_key = self._get_var(mapping.api_key_var)
        if not api_key:
            for alias in mapping.api_key_aliases:
                api_key = self._get_var(alias)
                if api_key:
                    break
        if not api_key:
            _logger.debug(
                "credential_validation_failed",
                provider=provider.value,
                reason="missing_key",
            )
            return False, f"Missing {mapping.api_key_var}"

        validation_result = _validate_key_format(provider, api_key)
        if validation_result is not None:
            _logger.warning(
                "credential_validation_failed",
                provider=provider.value,
                reason="invalid_format",
            )
            return False, validation_result

        _logger.debug(
            "credential_validated",
            provider=provider.value,
            valid=True,
        )
        return True, None

    def list_configured_providers(self) -> list[ProviderName]:
        """List all providers that have credentials configured.

        Returns:
            list[ProviderName]: List of provider names with valid credentials.
        """
        configured: list[ProviderName] = []
        for provider in ProviderName:
            is_valid, _ = self.validate_credentials(provider)
            if is_valid:
                configured.append(provider)
        _logger.debug(
            "configured_providers_listed",
            count=len(configured),
            providers=[p.value for p in configured],
        )
        return configured

    def list_missing_providers(self) -> list[ProviderName]:
        """List all providers that are missing credentials.

        Returns:
            list[ProviderName]: List of provider names without valid credentials.
        """
        missing: list[ProviderName] = []
        for provider in ProviderName:
            is_valid, _ = self.validate_credentials(provider)
            if not is_valid:
                missing.append(provider)
        _logger.debug(
            "missing_providers_listed",
            count=len(missing),
            providers=[p.value for p in missing],
        )
        return missing

    def set_env_var(self, name: str, value: str) -> None:
        """Set an environment variable (in memory only).

        Args:
            name: The environment variable name.
            value: The value to set.
        """
        self._env_vars[name] = value
        os.environ[name] = value

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
        lossless round-trip with the parser.

        Args:
            name: The environment variable name.
            value: The value to save.

        Raises:
            OSError: If the .env file cannot be read or written.
        """
        self.set_env_var(name, value)
        _logger.info("env_file_write_started", path=str(self.env_path), variable=name)

        quoted = _quote_env_value(value)
        new_line_body = f"{name}={quoted}"
        key_pattern = re.compile(rf"^(?:export\s+)?{re.escape(name)}\s*=.*$")

        existing_text = ""
        if self.env_path.exists():
            try:
                with self.env_path.open("r", encoding="utf-8", newline="") as f:
                    existing_text = f.read()
            except OSError:
                _logger.exception("env_file_read_existing_failed", path=str(self.env_path))
                raise

        eol = _detect_eol(existing_text) if existing_text else "\n"

        lines: list[str] = []
        key_found = False

        if existing_text:
            raw_lines = existing_text.splitlines(keepends=True)
            for raw_line in raw_lines:
                content = raw_line
                line_eol = ""
                if content.endswith("\r\n"):
                    line_eol = "\r\n"
                    content = content[:-2]
                elif content.endswith("\n"):
                    line_eol = "\n"
                    content = content[:-1]
                elif content.endswith("\r"):
                    line_eol = "\r"
                    content = content[:-1]

                if key_pattern.match(content.strip()):
                    replacement_eol = line_eol or eol
                    lines.append(f"{new_line_body}{replacement_eol}")
                    key_found = True
                else:
                    lines.append(f"{content}{line_eol}")

        if not key_found:
            if lines:
                last = lines[-1]
                if not last.endswith(("\n", "\r")):
                    lines[-1] = f"{last}{eol}"
            lines.append(f"{new_line_body}{eol}")

        self.env_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.env_path.open("w", encoding="utf-8", newline="") as f:
                f.writelines(lines)
        except OSError:
            _logger.exception("env_file_write_failed", path=str(self.env_path))
            raise

        _logger.info(
            "env_file_saved",
            path=str(self.env_path),
            variable=name,
            updated_existing=key_found,
        )


def get_api_key_env_var_mapping() -> dict[str, str]:
    """Get a mapping of provider ID to API key environment variable name.

    Derives the mapping from PROVIDER_MAPPINGS to maintain a single source
    of truth for env var names.

    Returns:
        dict[str, str]: Dict mapping provider ID string to API key env var name.
    """
    return {provider.value: mapping.api_key_var for provider, mapping in CredentialLoader.PROVIDER_MAPPINGS.items()}


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
    """Get the global credential loader instance.

    Returns:
        CredentialLoader: The singleton CredentialLoader instance.
    """
    return CredentialLoader()
