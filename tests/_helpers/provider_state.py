# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Isolation helpers for tests that exercise saved provider credentials and settings.

The sandbox runner forwards the host's real provider credentials into the test
process environment, and ``CredentialLoader`` both reads and writes
``os.environ``. Tests that assert which endpoint, key or timeout a provider
ends up with must therefore start from an environment containing none of the
variables the application or the provider SDKs consult, and must keep every
file they write inside the test's own temporary directory.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.config import get_state_root
from intellicrack.credentials.env_loader import CredentialLoader, get_credential_loader


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


_SDK_ENDPOINT_VARIABLES: Final[tuple[str, ...]] = (
    "ANTHROPIC_BASE_URL",
    "GOOGLE_GEMINI_BASE_URL",
    "GOOGLE_VERTEX_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT_ID",
)


def provider_environment_variables() -> tuple[str, ...]:
    """Return every environment variable that can influence a provider connection.

    Derived from ``CredentialLoader.PROVIDER_MAPPINGS`` so it cannot drift from
    the application's own variable names, plus the endpoint variables the
    provider SDKs read on their own.

    Returns:
        tuple[str, ...]: Sorted, de-duplicated variable names.
    """
    names: set[str] = set(_SDK_ENDPOINT_VARIABLES)
    for mapping in CredentialLoader.PROVIDER_MAPPINGS.values():
        candidates = (mapping.api_key_var, *mapping.api_key_aliases, mapping.api_base_var, mapping.organization_var, mapping.project_var)
        names.update(name for name in candidates if name)
    return tuple(sorted(names))


def isolate_provider_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every provider-related variable from the process environment for one test.

    ``monkeypatch`` restores the original values, and removes any value a
    ``CredentialLoader`` injected during the test, when the test finishes.

    Args:
        monkeypatch: The test's monkeypatch fixture.
    """
    for name in provider_environment_variables():
        monkeypatch.delenv(name, raising=False)


@contextlib.contextmanager
def redirected_state_root(monkeypatch: pytest.MonkeyPatch, base: Path) -> Generator[Path]:
    r"""Point the application's per-user state root at a private directory.

    Uses the installed launcher's own mechanism: ``INTELLICRACK_STATE_DIR``
    naming an ``Intellicrack`` directory under ``%LOCALAPPDATA%``. Both
    ``.env`` and ``.intellicrack\providers.json`` then resolve inside ``base``,
    and the global credential loader is rebuilt for the redirected root on
    entry and discarded on exit.

    Args:
        monkeypatch: The test's monkeypatch fixture.
        base: A directory private to the test.

    Yields:
        Path: The resolved state root.
    """
    local_app_data = base / "LocalAppData"
    state_dir = local_app_data / "Intellicrack"
    state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("INTELLICRACK_STATE_DIR", str(state_dir))

    resolved = get_state_root()
    if resolved != state_dir.resolve():
        pytest.fail(f"state root redirection was rejected: resolved {resolved}, expected {state_dir.resolve()}")

    get_credential_loader.cache_clear()
    try:
        yield resolved
    finally:
        get_credential_loader.cache_clear()
