# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Credential management for Intellicrack.

This module handles loading and validating API credentials from .env files
for various LLM providers.
"""

from __future__ import annotations

import functools
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from ..core.logging import get_logger
from ..core.types import ProviderCredentials, ProviderName


_logger = get_logger("credentials.env_loader")


@dataclass
class ProviderCredentialMapping:
    """Mapping of environment variable names for a provider.

    Attributes:
        api_key_var: Environment variable name for API key.
        api_base_var: Environment variable name for custom API base URL.
        organization_var: Environment variable name for organization ID.
        project_var: Environment variable name for project ID.
    """

    api_key_var: str
    api_base_var: str | None = None
    organization_var: str | None = None
    project_var: str | None = None


def _find_env_file() -> Path:
    """Find the .env file by searching up the directory tree.

    Returns:
        Path to the found .env file or default location.
    """
    search_paths = [
        Path.cwd() / ".env",
        Path("D:/Intellicrack/.env"),
        Path.home() / ".env",
    ]

    _logger.debug(
        "env_file_search",
        extra={"paths_checked": [str(p) for p in search_paths]},
    )

    for path in search_paths:
        if path.exists():
            _logger.info("env_file_found", extra={"path": str(path)})
            return path

    _logger.debug("env_file_not_found", extra={"default_path": "D:/Intellicrack/.env"})
    return Path("D:/Intellicrack/.env")


def _validate_key_format(provider: ProviderName, api_key: str) -> str | None:
    """Validate API key format for a provider.

    Args:
        provider: The provider the key is for.
        api_key: The API key to validate.

    Returns:
        Error message if invalid, None if valid.
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
        env_path: Path to the .env file.
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
        ),
    }

    def __init__(self, env_path: Path | None = None) -> None:
        """Initialize the credential loader.

        Args:
            env_path: Path to the .env file. If None, searches for .env
                     in current directory and parent directories.
        """
        if env_path is None:
            env_path = _find_env_file()
        self.env_path = env_path
        self._env_vars: dict[str, str] = {}
        self._load_env_file()

    def _load_env_file(self) -> None:
        """Load environment variables from .env file.

        Parses the .env file and loads variables into the internal dict.
        Also sets them in os.environ for compatibility with other libraries.
        """
        if not self.env_path.exists():
            _logger.debug(
                "env_file_missing",
                extra={"path": str(self.env_path)},
            )
            return

        env_pattern = re.compile(
            r"^(?:export\s+)?"
            r"([A-Za-z_][A-Za-z0-9_]*)"
            r"\s*=\s*"
            r'(?:"([^"]*)"|\'([^\']*)\'|(.*))'
            r"\s*$"
        )

        loaded_count = 0
        with self.env_path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                stripped_line = raw_line.strip()

                if not stripped_line or stripped_line.startswith("#"):
                    continue

                if match := env_pattern.match(stripped_line):
                    key = match[1]
                    value = match[2] or match[3] or match[4] or ""
                    value = value.strip()
                    self._env_vars[key] = value
                    os.environ[key] = value
                    loaded_count += 1

        _logger.info(
            "env_variables_loaded",
            extra={"path": str(self.env_path), "count": loaded_count},
        )

    def reload(self) -> None:
        """Reload credentials from the .env file.

        Call this method to pick up changes to the .env file
        without restarting the application.
        """
        _logger.debug("env_file_reloading", extra={"path": str(self.env_path)})
        self._env_vars.clear()
        self._load_env_file()
        _logger.info("env_file_reloaded", extra={"path": str(self.env_path)})

    def get_credentials(self, provider: ProviderName) -> ProviderCredentials | None:
        """Get credentials for a specific provider.

        Args:
            provider: The LLM provider to get credentials for.

        Returns:
            ProviderCredentials if found and valid, None otherwise.
        """
        mapping = self.PROVIDER_MAPPINGS.get(provider)
        if mapping is None:
            _logger.debug(
                "credential_provider_unknown",
                extra={"provider": provider.value},
            )
            return None

        api_key = self._get_var(mapping.api_key_var)
        if not api_key:
            _logger.debug(
                "credential_not_found",
                extra={"provider": provider.value},
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
            extra={
                "provider": provider.value,
                "has_api_base": api_base is not None,
                "has_organization_id": organization_id is not None,
                "has_project_id": project_id is not None,
            },
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
            Variable value or None if not found.
        """
        if value := self._env_vars.get(name):
            return value
        return os.environ.get(name)

    def validate_credentials(self, provider: ProviderName) -> tuple[bool, str | None]:
        """Validate that credentials exist and are properly formatted.

        Args:
            provider: The provider to validate credentials for.

        Returns:
            Tuple of (is_valid, error_message). error_message is None if valid.
        """
        mapping = self.PROVIDER_MAPPINGS.get(provider)
        if mapping is None:
            _logger.debug(
                "credential_validation_failed",
                extra={"provider": provider.value, "reason": "unknown_provider"},
            )
            return False, f"Unknown provider: {provider.value}"

        api_key = self._get_var(mapping.api_key_var)
        if not api_key:
            _logger.debug(
                "credential_validation_failed",
                extra={"provider": provider.value, "reason": "missing_key"},
            )
            return False, f"Missing {mapping.api_key_var}"

        validation_result = _validate_key_format(provider, api_key)
        if validation_result is not None:
            _logger.warning(
                "credential_validation_failed",
                extra={"provider": provider.value, "reason": "invalid_format"},
            )
            return False, validation_result

        _logger.debug(
            "credential_validated",
            extra={"provider": provider.value, "valid": True},
        )
        return True, None

    def list_configured_providers(self) -> list[ProviderName]:
        """List all providers that have credentials configured.

        Returns:
            List of provider names with valid credentials.
        """
        configured: list[ProviderName] = []
        for provider in ProviderName:
            is_valid, _ = self.validate_credentials(provider)
            if is_valid:
                configured.append(provider)
        _logger.debug(
            "configured_providers_listed",
            extra={"count": len(configured), "providers": [p.value for p in configured]},
        )
        return configured

    def list_missing_providers(self) -> list[ProviderName]:
        """List all providers that are missing credentials.

        Returns:
            List of provider names without valid credentials.
        """
        missing: list[ProviderName] = []
        for provider in ProviderName:
            is_valid, _ = self.validate_credentials(provider)
            if not is_valid:
                missing.append(provider)
        _logger.debug(
            "missing_providers_listed",
            extra={"count": len(missing), "providers": [p.value for p in missing]},
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
            The variable value, or default if not found.
        """
        value = self._env_vars.get(name)
        if value is not None:
            return value
        return os.environ.get(name, default)

    def save_to_env_file(self, name: str, value: str) -> None:
        """Save an environment variable to the .env file.

        Updates an existing variable or adds a new one at the end of the file.
        Preserves comments and file structure.

        Args:
            name: The environment variable name.
            value: The value to save.
        """
        self.set_env_var(name, value)
        _logger.debug("env_file_write_started", extra={"path": str(self.env_path), "variable": name})

        lines: list[str] = []
        key_found = False
        key_pattern = re.compile(rf"^(?:export\s+)?{re.escape(name)}\s*=.*$")

        if self.env_path.exists():
            with self.env_path.open("r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.rstrip("\n\r")
                    if key_pattern.match(stripped):
                        lines.append(f"{name}={value}\n")
                        key_found = True
                    else:
                        lines.append(line if line.endswith("\n") else line + "\n")

        if not key_found:
            if lines and not lines[-1].endswith("\n"):
                lines.append("\n")
            lines.append(f"{name}={value}\n")

        self.env_path.parent.mkdir(parents=True, exist_ok=True)
        with self.env_path.open("w", encoding="utf-8") as f:
            f.writelines(lines)

        _logger.info(
            "env_file_saved",
            extra={
                "path": str(self.env_path),
                "variable": name,
                "updated_existing": key_found,
            },
        )


def create_env_template(path: Path) -> None:
    """Create a template .env file with all supported providers.

    Args:
        path: Path where to create the .env.example file.
    """
    template = """# Intellicrack API Credentials
# Copy this file to .env and fill in your API keys

# Anthropic (Claude)
ANTHROPIC_API_KEY=sk-ant-api03-...

# OpenAI (GPT)
OPENAI_API_KEY=sk-...
# OPENAI_ORGANIZATION=org-...
# OPENAI_API_BASE=https://api.openai.com/v1

# Google AI (Gemini)
GOOGLE_API_KEY=...
# GOOGLE_CLOUD_PROJECT=your-project-id

# OpenRouter
OPENROUTER_API_KEY=sk-or-v1-...

# Ollama (local)
# OLLAMA_HOST=http://localhost:11434
# OLLAMA_API_KEY=  # Usually not needed for local
"""

    _logger.debug("env_template_creating", extra={"path": str(path)})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write(template)
    _logger.debug("env_template_created", extra={"path": str(path)})


@functools.lru_cache(maxsize=1)
def get_credential_loader() -> CredentialLoader:
    """Get the global credential loader instance.

    Returns:
        The singleton CredentialLoader instance.
    """
    return CredentialLoader()
