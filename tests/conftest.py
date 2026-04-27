# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Global pytest fixtures for Intellicrack tests.

This module provides shared fixtures for credential loading, API key availability
checks, XPU hardware detection, and common test utilities used across all test
modules. It also wires in the suite-wide process cleanup safety net:

* The :func:`pytest_configure` hook registers the ``spawns_process`` marker.
* The :func:`pytest_collection_modifyitems` hook auto-skips tests marked with
  ``spawns_process`` when running outside the Intellicrack Docker sandbox,
  unless the operator sets ``INTELLICRACK_ALLOW_HOST_PROCESS_TESTS=1``. This
  mechanism prevents notepad / ollama / debuggee processes from spawning on
  a developer's host when pytest is invoked directly.
* The :func:`process_orphan_killer` autouse session fixture snapshots the
  pytest interpreter's descendants at session start and forcibly terminates
  any new descendants left over at session end as a final safety net.

Sandbox isolation itself is handled by the Docker-based harness at
``scripts/sandbox/docker_sandbox.py``; pytest itself runs normally here.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import httpx
import pytest

from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.providers.xpu_utils import is_arc_b580, is_xpu_available
from tests._helpers.process_cleanup import (
    ALLOW_HOST_PROCESS_TESTS_ENV,
    SANDBOX_ENV_VAR,
    allow_host_process_tests,
    is_sandboxed,
    kill_new_descendants,
    snapshot_descendants,
)


if TYPE_CHECKING:
    from collections.abc import Generator


_HTTP_OK = 200

_SPAWNS_PROCESS_MARKER = "spawns_process"
_HOST_SKIP_REASON = (
    f"Test spawns external processes; refusing to run on host. Use "
    f"'just test' (Docker sandbox) or set {ALLOW_HOST_PROCESS_TESTS_ENV}=1 "
    "to override."
)

_logger = get_logger("tests.conftest")


def pytest_configure(config: pytest.Config) -> None:
    """Register Intellicrack-specific pytest markers.

    Args:
        config: Active pytest configuration object.
    """
    config.addinivalue_line(
        "markers",
        f"{_SPAWNS_PROCESS_MARKER}: test spawns external OS processes; runs only inside the Docker sandbox",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Skip ``spawns_process`` tests when not running inside the Docker sandbox.

    Tests that spawn real processes (notepad, ollama, target binaries, debuggee
    processes) are intended to run only inside the Intellicrack Docker test
    sandbox. When pytest is invoked directly on the host, those tests would
    leak processes onto the developer's machine, so they are auto-skipped
    unless :data:`tests._helpers.process_cleanup.ALLOW_HOST_PROCESS_TESTS_ENV`
    is truthy.

    Args:
        config: Active pytest configuration object.
        items: Mutable list of collected test items to filter.
    """
    del config
    if is_sandboxed() or allow_host_process_tests():
        return
    skip_marker = pytest.mark.skip(reason=_HOST_SKIP_REASON)
    for item in items:
        if item.get_closest_marker(_SPAWNS_PROCESS_MARKER) is not None:
            item.add_marker(skip_marker)


@pytest.fixture(autouse=True, scope="session")
def process_orphan_killer() -> Generator[None]:
    """Kill any descendant processes that survive past session teardown.

    Snapshots the pytest interpreter's descendant PID set at session start;
    on teardown, forcibly terminates any descendants that were spawned during
    the run and are still alive. This is a defence in depth against fixtures
    that fail to clean up (assertion failures, timeouts, ``KeyboardInterrupt``,
    or third-party libraries that fork without registering with our
    :class:`tests._helpers.process_cleanup.ManagedProcess` wrapper).

    Yields:
        None: Yields control to the test session.
    """
    baseline = snapshot_descendants()
    try:
        yield
    finally:
        leaked = kill_new_descendants(baseline)
        if leaked:
            _logger.warning(
                "tests_process_leak_swept",
                leaked_pids=leaked,
                sandboxed=is_sandboxed(),
                sandbox_env=SANDBOX_ENV_VAR,
            )


@pytest.fixture(autouse=True)
def process_per_test_orphan_killer(request: pytest.FixtureRequest) -> Generator[None]:
    """Kill leftover descendants per test for ``spawns_process``-marked items.

    The session-level :func:`process_orphan_killer` reaps descendants only at
    session end; that's too late for fast iterative test runs where dozens of
    leaked debuggees would pile up between tests. This per-test fixture scopes
    the safety net to each individual test marked with ``spawns_process``,
    snapshotting descendants before the test runs and killing any new ones
    that remain after teardown.

    The fixture is a no-op for tests without the marker so it adds zero
    overhead to the non-process-spawning unit tests.

    Args:
        request: The pytest fixture request object used to inspect markers.

    Yields:
        None: Yields control to the test.
    """
    node = cast("pytest.Item", request.node)
    if node.get_closest_marker(_SPAWNS_PROCESS_MARKER) is None:
        yield
        return
    baseline = snapshot_descendants()
    try:
        yield
    finally:
        leaked = kill_new_descendants(baseline)
        if leaked:
            _logger.warning(
                "tests_process_leak_swept_per_test",
                leaked_pids=leaked,
                test_id=node.nodeid,
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
