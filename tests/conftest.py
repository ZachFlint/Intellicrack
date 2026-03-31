# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Global pytest fixtures for Intellicrack tests.

This module provides shared fixtures for credential loading, API key availability
checks, XPU hardware detection, and common test utilities used across all test modules.

When running on a Windows host (not inside Windows Sandbox and not in CI), tests are
automatically redirected to run inside Windows Sandbox for process and registry isolation.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.providers.xpu_utils import is_arc_b580, is_xpu_available


_HTTP_OK = 200
_SANDBOX_LAUNCHER = Path(r"D:\Sandbox\shared\launch_sandbox_test.ps1")
_REPORTS_DIR = Path(r"D:\Intellicrack\reports\tests")
_SANDBOX_ARGS_FILE = _REPORTS_DIR / "_sandbox_pytest_args.txt"

_sandbox_logger = logging.getLogger("intellicrack.sandbox_redirect")


def pytest_configure(config: pytest.Config) -> None:
    """Redirect test execution to Windows Sandbox when running on the host.

    Checks whether tests are running inside Windows Sandbox by looking for
    the ``INTELLICRACK_SANDBOXED`` environment variable. Setting
    ``INTELLICRACK_LOCAL_TESTS=1`` bypasses sandbox redirection and runs
    tests directly on the local system. When not sandboxed, launches Windows
    Sandbox with the current pytest arguments and streams the output back to
    the caller. Falls back to local execution if sandbox infrastructure is
    unavailable.

    Args:
        config: The pytest configuration object.
    """
    if os.environ.get("INTELLICRACK_SANDBOXED") == "1":
        return
    if os.environ.get("INTELLICRACK_LOCAL_TESTS") == "1":
        return
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        return
    if not _SANDBOX_LAUNCHER.exists():
        return
    if not shutil.which("gsudo"):
        _sandbox_logger.warning("gsudo not found, running tests locally")
        return

    raw_args = [str(a) for a in config.invocation_params.args]
    args_str = " ".join(raw_args)

    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    _SANDBOX_ARGS_FILE.write_text(args_str, encoding="utf-8")

    cmd = [
        "gsudo",
        "pwsh",
        "-NoLogo",
        "-File",
        str(_SANDBOX_LAUNCHER),
        "-TestType",
        "custom",
    ]

    try:
        result = subprocess.run(cmd, cwd=r"D:\Intellicrack", check=False)
    except OSError:
        _sandbox_logger.warning("Failed to launch sandbox, running tests locally")
        return

    pytest.exit(
        reason=f"Tests executed in Windows Sandbox (exit code: {result.returncode})",
        returncode=result.returncode,
    )


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Get the project root directory.

    Returns:
        Path: Path to the Intellicrack project root.
    """
    return Path("D:/Intellicrack")


@pytest.fixture(scope="session")
def env_file_path(project_root: Path) -> Path:
    """Get the path to the .env file.

    Args:
        project_root: The project root directory.

    Returns:
        Path: Path to the .env file.
    """
    return project_root / ".env"


@pytest.fixture(scope="session")
def credential_loader(env_file_path: Path) -> CredentialLoader:
    """Create a CredentialLoader instance.

    This fixture loads credentials from the project's .env file.
    Tests should use this to check credential availability and
    obtain credentials for provider connections.

    Args:
        env_file_path: Path to the .env file.

    Returns:
        CredentialLoader: A configured CredentialLoader instance.
    """
    return CredentialLoader(env_path=env_file_path)


@pytest.fixture(scope="session")
def has_anthropic_key(credential_loader: CredentialLoader) -> bool:
    """Check if Anthropic API key is configured and valid format.

    Args:
        credential_loader: The credential loader instance.

    Returns:
        bool: True if a valid Anthropic API key is configured.
    """
    is_valid, _ = credential_loader.validate_credentials(ProviderName.ANTHROPIC)
    return is_valid


@pytest.fixture(scope="session")
def has_openai_key(credential_loader: CredentialLoader) -> bool:
    """Check if OpenAI API key is configured and valid format.

    Args:
        credential_loader: The credential loader instance.

    Returns:
        bool: True if a valid OpenAI API key is configured.
    """
    is_valid, _ = credential_loader.validate_credentials(ProviderName.OPENAI)
    return is_valid


@pytest.fixture(scope="session")
def has_google_key(credential_loader: CredentialLoader) -> bool:
    """Check if Google API key is configured.

    Args:
        credential_loader: The credential loader instance.

    Returns:
        bool: True if a Google API key is configured.
    """
    is_valid, _ = credential_loader.validate_credentials(ProviderName.GOOGLE)
    return is_valid


@pytest.fixture(scope="session")
def has_openrouter_key(credential_loader: CredentialLoader) -> bool:
    """Check if OpenRouter API key is configured and valid format.

    Args:
        credential_loader: The credential loader instance.

    Returns:
        bool: True if a valid OpenRouter API key is configured.
    """
    is_valid, _ = credential_loader.validate_credentials(ProviderName.OPENROUTER)
    return is_valid


@pytest.fixture(scope="session")
def has_huggingface_key(credential_loader: CredentialLoader) -> bool:
    """Check if HuggingFace API token is configured and valid format.

    Args:
        credential_loader: The credential loader instance.

    Returns:
        bool: True if a valid HuggingFace API token is configured.
    """
    is_valid, _ = credential_loader.validate_credentials(ProviderName.HUGGINGFACE)
    return is_valid


@pytest.fixture(scope="session")
def has_grok_key(credential_loader: CredentialLoader) -> bool:
    """Check if Grok (X.AI) API key is configured and valid format.

    Args:
        credential_loader: The credential loader instance.

    Returns:
        bool: True if a valid Grok API key is configured.
    """
    is_valid, _ = credential_loader.validate_credentials(ProviderName.GROK)
    return is_valid


@pytest.fixture(scope="session")
def has_ollama_available() -> bool:
    """Check if Ollama is running locally.

    Attempts to connect to the default Ollama endpoint to verify
    the service is available for testing.

    Returns:
        bool: True if Ollama is running and responding.
    """
    try:
        response = httpx.get(
            "http://localhost:11434/api/tags",
            timeout=5.0,
        )
    except (OSError, httpx.HTTPError):
        return False
    else:
        return response.status_code == _HTTP_OK


@pytest.fixture(scope="session")
def configured_providers(credential_loader: CredentialLoader) -> list[ProviderName]:
    """Get list of providers with valid credentials configured.

    Args:
        credential_loader: The credential loader instance.

    Returns:
        list[ProviderName]: List of ProviderName enums for configured providers.
    """
    return credential_loader.list_configured_providers()


@pytest.fixture(scope="session")
def anthropic_credentials(
    credential_loader: CredentialLoader,
    *,
    has_anthropic_key: bool,
) -> ProviderCredentials | None:
    """Get Anthropic credentials if available.

    Args:
        credential_loader: The credential loader instance.
        has_anthropic_key: Whether Anthropic key is configured.

    Returns:
        ProviderCredentials | None: ProviderCredentials for Anthropic or None if not configured.
    """
    if not has_anthropic_key:
        return None
    return credential_loader.get_credentials(ProviderName.ANTHROPIC)


@pytest.fixture(scope="session")
def openai_credentials(
    credential_loader: CredentialLoader,
    *,
    has_openai_key: bool,
) -> ProviderCredentials | None:
    """Get OpenAI credentials if available.

    Args:
        credential_loader: The credential loader instance.
        has_openai_key: Whether OpenAI key is configured.

    Returns:
        ProviderCredentials | None: ProviderCredentials for OpenAI or None if not configured.
    """
    if not has_openai_key:
        return None
    return credential_loader.get_credentials(ProviderName.OPENAI)


@pytest.fixture(scope="session")
def google_credentials(
    credential_loader: CredentialLoader,
    *,
    has_google_key: bool,
) -> ProviderCredentials | None:
    """Get Google credentials if available.

    Args:
        credential_loader: The credential loader instance.
        has_google_key: Whether Google key is configured.

    Returns:
        ProviderCredentials | None: ProviderCredentials for Google or None if not configured.
    """
    if not has_google_key:
        return None
    return credential_loader.get_credentials(ProviderName.GOOGLE)


@pytest.fixture(scope="session")
def openrouter_credentials(
    credential_loader: CredentialLoader,
    *,
    has_openrouter_key: bool,
) -> ProviderCredentials | None:
    """Get OpenRouter credentials if available.

    Args:
        credential_loader: The credential loader instance.
        has_openrouter_key: Whether OpenRouter key is configured.

    Returns:
        ProviderCredentials | None: ProviderCredentials for OpenRouter or None if not configured.
    """
    if not has_openrouter_key:
        return None
    return credential_loader.get_credentials(ProviderName.OPENROUTER)


@pytest.fixture(scope="session")
def ollama_credentials(
    credential_loader: CredentialLoader,
) -> ProviderCredentials:
    """Get Ollama credentials (may be empty for local).

    Args:
        credential_loader: The credential loader instance.

    Returns:
        ProviderCredentials: ProviderCredentials for Ollama (may have empty api_key for local).
    """
    creds = credential_loader.get_credentials(ProviderName.OLLAMA)
    if creds is None:
        return ProviderCredentials(
            api_key=None,
            api_base="http://localhost:11434",
        )
    return creds


@pytest.fixture(scope="session")
def huggingface_credentials(
    credential_loader: CredentialLoader,
    *,
    has_huggingface_key: bool,
) -> ProviderCredentials | None:
    """Get HuggingFace credentials if available.

    Args:
        credential_loader: The credential loader instance.
        has_huggingface_key: Whether HuggingFace token is configured.

    Returns:
        ProviderCredentials | None: ProviderCredentials for HuggingFace or None if not configured.
    """
    if not has_huggingface_key:
        return None
    return credential_loader.get_credentials(ProviderName.HUGGINGFACE)


@pytest.fixture(scope="session")
def grok_credentials(
    credential_loader: CredentialLoader,
    *,
    has_grok_key: bool,
) -> ProviderCredentials | None:
    """Get Grok (X.AI) credentials if available.

    Args:
        credential_loader: The credential loader instance.
        has_grok_key: Whether Grok key is configured.

    Returns:
        ProviderCredentials | None: ProviderCredentials for Grok or None if not configured.
    """
    if not has_grok_key:
        return None
    return credential_loader.get_credentials(ProviderName.GROK)


@pytest.fixture(scope="session")
def has_xpu_available() -> bool:
    """Check if Intel XPU is available.

    Returns:
        bool: True if at least one XPU device is available.
    """
    return is_xpu_available()


@pytest.fixture(scope="session")
def has_arc_b580() -> bool:
    """Check if an Intel Arc B580 GPU is available.

    Returns:
        bool: True if an Arc B580 is detected.
    """
    return is_arc_b580()
