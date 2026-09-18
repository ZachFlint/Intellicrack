# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on reading provider settings written by an older build.

A saved timeout of 120 seconds is ambiguous, and the schema version resolves
it. Before settings were versioned, 120 was the dialog's untouched default, so
an unversioned 120 means "use the provider default". From version 2 on, the
default was stored as ``null``, so a versioned 120 was chosen deliberately.

That rule has to be tested against the version that introduced it, not the
current one. Tying it to the current version meant that moving the schema from
2 to 3 reclassified every v2 file as pre-versioning legacy and silently threw
away the 120-second timeouts users had set on purpose -- on upgrade, with no
error, which is the one moment nobody is looking.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from intellicrack.credentials.provider_settings import (
    LEGACY_DEFAULT_TIMEOUT_SECONDS,
    SCHEMA_VERSION_KEY,
    SETTINGS_SCHEMA_VERSION,
    TIMEOUT_SECONDS_KEY,
    VERSIONED_SCHEMA_FLOOR,
    ProviderSettingsStore,
    saved_timeout_seconds,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_the_floor_is_older_than_the_current_version() -> None:
    """The floor must name history, so a schema bump can never move it.

    If the two ever coincide again, every section written by the previous
    versioned build falls below the floor and is misread as legacy.
    """
    assert VERSIONED_SCHEMA_FLOOR == 2
    assert SETTINGS_SCHEMA_VERSION > VERSIONED_SCHEMA_FLOOR


def test_an_unversioned_120_means_the_provider_default() -> None:
    """A pre-versioning section's 120 was the untouched default, not a choice."""
    assert saved_timeout_seconds({TIMEOUT_SECONDS_KEY: LEGACY_DEFAULT_TIMEOUT_SECONDS}) is None


@pytest.mark.parametrize("version", [VERSIONED_SCHEMA_FLOOR, SETTINGS_SCHEMA_VERSION])
def test_a_versioned_120_is_kept(version: int) -> None:
    """Every versioned build stored its default as null, so its 120 is deliberate.

    Args:
        version: The schema version the section was written with.
    """
    section = {TIMEOUT_SECONDS_KEY: LEGACY_DEFAULT_TIMEOUT_SECONDS, SCHEMA_VERSION_KEY: version}
    assert saved_timeout_seconds(section) == LEGACY_DEFAULT_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    ("section", "expected"),
    [
        ({TIMEOUT_SECONDS_KEY: 45}, 45),
        ({TIMEOUT_SECONDS_KEY: 45, SCHEMA_VERSION_KEY: 2}, 45),
        ({TIMEOUT_SECONDS_KEY: None, SCHEMA_VERSION_KEY: 2}, None),
        ({TIMEOUT_SECONDS_KEY: 120, SCHEMA_VERSION_KEY: True}, None),
    ],
)
def test_only_the_legacy_120_is_reinterpreted(section: dict[str, object], expected: float | None) -> None:
    """The legacy rule is narrow: it touches an unversioned 120 and nothing else.

    A boolean schema version is not a version, so it falls back to legacy
    handling rather than being read as 1.

    Args:
        section: A saved provider section.
        expected: The timeout that section must resolve to.
    """
    assert saved_timeout_seconds(section) == expected


def test_a_v2_file_keeps_its_timeout_through_the_real_store(tmp_path: Path) -> None:
    """Load a file an older build wrote and read the timeout back through the store.

    Exercises the on-disk path the application takes at startup, not just the
    helper, because that is where an upgrade actually loses the value.

    Args:
        tmp_path: Per-test directory holding the settings file.
    """
    settings_path = tmp_path / "providers.json"
    _ = settings_path.write_text(
        json.dumps({"anthropic": {"enabled": True, TIMEOUT_SECONDS_KEY: 120, SCHEMA_VERSION_KEY: 2}}),
        encoding="utf-8",
    )

    store = ProviderSettingsStore(settings_path)

    assert store.timeout_seconds("anthropic") == LEGACY_DEFAULT_TIMEOUT_SECONDS
