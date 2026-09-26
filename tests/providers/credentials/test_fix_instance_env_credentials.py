# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for how user-defined provider instances map onto ``.env`` variables.

Every gate drives the real :class:`CredentialLoader` against a real ``.env``
file and the real :class:`ProviderSettingsStore` against a real
``providers.json`` under ``tmp_path``. They fail when:

* a value carrying a character ``str.splitlines`` treats as a line boundary
  (U+2028, U+2029, NEL, vertical tab, form feed, U+001C to U+001E) is cut
  short when the file is read back, or corrupts the next variable;
* two instance ids share variables (``my-gw`` / ``my_gw``), an instance id
  reads a built-in provider's variable (``xai``, ``gemini``, ``google_cloud``)
  or derives a name no parser accepts (``1gw``), and the loader and the
  creation rule disagree about it;
* an instance created from a preset ignores the key variable that preset
  names, a duplicated built-in borrows the built-in's key, or clearing the
  instance's key deletes the preset's shared variable;
* the credential-source label, the configured-provider overview and the
  startup connect policy ignore user-defined instances.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from intellicrack.credentials.env_loader import (
    CredentialField,
    CredentialLoader,
    EnvPersistAction,
    instance_env_var_conflict,
    unregister_instance_mapping,
)
from intellicrack.credentials.provider_settings import ProviderSettingsStore
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.instances import ProviderInstance, instance_from_preset_id
from intellicrack.ui.provider_config import CredentialSource, CredentialSourceDetector
from tests._helpers.provider_state import isolate_provider_environment


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_LINE_SEPARATORS: tuple[tuple[str, str], ...] = (
    ("line_separator", "\u2028"),
    ("paragraph_separator", "\u2029"),
    ("next_line", "\x85"),
    ("vertical_tab", "\x0b"),
    ("form_feed", "\x0c"),
    ("file_separator", "\x1c"),
    ("group_separator", "\x1d"),
    ("record_separator", "\x1e"),
)

_INSTANCE_IDS: tuple[str, ...] = ("my-gw", "my_gw", "xai", "gemini", "google_cloud", "1gw", "ds", "openai-copy", "keyless")


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove provider variables and forget instance mappings registered by a gate.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        None: Control passes to the gate.
    """
    isolate_provider_environment(monkeypatch)
    for name in ("MY_GW_API_KEY", "DS_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_COPY_API_KEY", "KEYLESS_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    yield
    for instance_id in _INSTANCE_IDS:
        unregister_instance_mapping(instance_id)


def _write_instances(path: Path, records: dict[str, dict[str, object]]) -> None:
    """Write a ``providers.json`` holding exactly these instance records.

    Args:
        path: The ``providers.json`` path.
        records: Instance records keyed by the id they are stored under.
    """
    _ = path.write_text(json.dumps({"instances": records}, indent=2), encoding="utf-8")


@pytest.mark.parametrize(("label", "separator"), _LINE_SEPARATORS, ids=[label for label, _ in _LINE_SEPARATORS])
def test_env_writer_round_trips_every_splitlines_separator(tmp_path: Path, label: str, separator: str) -> None:
    """A value holding a line separator is read back whole and leaves the next variable intact.

    Args:
        tmp_path: Per-test temporary directory.
        label: Human-readable separator name.
        separator: The separator character.
    """
    env_path = tmp_path / ".env"
    value = f"key-{label}{separator}tail{separator}"
    writer = CredentialLoader(env_path)
    writer.save_to_env_file("SEPARATED_VALUE", value)
    writer.save_to_env_file("AFTER_VALUE", "kept")

    raw = env_path.read_text(encoding="utf-8")
    assert separator not in raw, f"{label} was written raw into .env"
    reloaded = CredentialLoader(env_path)
    assert reloaded.get_saved_var("SEPARATED_VALUE") == value
    assert reloaded.get_saved_var("AFTER_VALUE") == "kept"

    writer.save_to_env_file("SEPARATED_VALUE", f"updated{separator}value")
    assert CredentialLoader(env_path).get_saved_var("SEPARATED_VALUE") == f"updated{separator}value"
    assert CredentialLoader(env_path).get_saved_var("AFTER_VALUE") == "kept"


def test_env_reader_keeps_a_hand_written_separator_inside_its_line(tmp_path: Path) -> None:
    """A separator typed straight into a quoted value neither truncates it nor spawns a variable.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = tmp_path / ".env"
    _ = env_path.write_text('RAW_VALUE="head\u2028INJECTED=1"\nNEXT=2\n', encoding="utf-8")

    loader = CredentialLoader(env_path)

    assert loader.get_saved_var("RAW_VALUE") == "head\u2028INJECTED=1"
    assert loader.get_saved_var("INJECTED") is None
    assert loader.get_saved_var("NEXT") == "2"


@pytest.mark.parametrize(
    ("instance_id", "others", "fragment"),
    [
        ("my_gw", ("my-gw",), "MY_GW_API_KEY"),
        ("xai", (), "XAI_API_KEY"),
        ("gemini", (), "GEMINI_API_KEY"),
        ("google_cloud", (), "GOOGLE_CLOUD_PROJECT"),
        ("1gw", (), "1GW_API_KEY"),
        ("local-transformers", provider_ids.BUILTIN_PROVIDER_IDS, "LOCAL_TRANSFORMERS_API_KEY"),
        ("openai", (), "built-in"),
    ],
)
def test_instance_ids_that_cannot_own_their_variables_are_refused(instance_id: str, others: tuple[str, ...], fragment: str) -> None:
    """Colliding, reserved and unparseable ids are refused with a reason naming the variable.

    Args:
        instance_id: The candidate id.
        others: Ids already in use.
        fragment: Text the refusal must contain.
    """
    reason = instance_env_var_conflict(instance_id, others)
    assert reason is not None
    assert fragment in reason


def test_distinct_instance_ids_are_accepted() -> None:
    """Ids with their own, valid variables are accepted."""
    assert instance_env_var_conflict("my-gw", ("other-gw", *provider_ids.BUILTIN_PROVIDER_IDS)) is None
    assert instance_env_var_conflict("gw1", provider_ids.BUILTIN_PROVIDER_IDS) is None


def test_loader_skips_the_same_ids_the_creation_rule_refuses(tmp_path: Path) -> None:
    """A hand-edited ``providers.json`` cannot make two instances read one variable.

    Args:
        tmp_path: Per-test temporary directory.
    """
    settings = tmp_path / "providers.json"
    records: dict[str, dict[str, object]] = {}
    for instance_id in ("my-gw", "my_gw", "xai", "gemini", "google_cloud", "1gw", "openai"):
        record: dict[str, object] = dict(ProviderInstance(instance_id="placeholder", api_base="http://127.0.0.1:1/v1").to_mapping())
        record["instance_id"] = instance_id
        records[instance_id] = record
    _write_instances(settings, records)

    loaded = ProviderSettingsStore(settings).load_instances()

    assert list(loaded) == ["my-gw"]
    assert ProviderSettingsStore(settings).stored_instance_ids() == frozenset(records)


def test_preset_key_variable_is_read_for_an_instance_under_another_id(tmp_path: Path) -> None:
    """An instance named ``ds`` created from the DeepSeek preset finds ``DEEPSEEK_API_KEY``.

    The key the user types is saved under the instance's own variable, and
    clearing it removes only that variable, never the preset's shared one.

    Args:
        tmp_path: Per-test temporary directory.
    """
    settings = tmp_path / "providers.json"
    instance = instance_from_preset_id("deepseek", instance_id="ds")
    assert instance is not None
    _write_instances(settings, {"ds": instance.to_mapping()})
    env_path = tmp_path / ".env"
    _ = env_path.write_text("DEEPSEEK_API_KEY=sk-deepseek-shared\n", encoding="utf-8")

    assert "ds" in ProviderSettingsStore(settings).load_instances()
    loader = CredentialLoader(env_path)
    assert loader.get_field("ds", CredentialField.API_KEY) == "sk-deepseek-shared"

    assert loader.persist_field("ds", CredentialField.API_KEY, "sk-ds-own") is EnvPersistAction.WRITTEN
    reloaded = CredentialLoader(env_path)
    assert reloaded.get_saved_var("DS_API_KEY") == "sk-ds-own"
    assert reloaded.get_field("ds", CredentialField.API_KEY) == "sk-ds-own"

    assert reloaded.persist_field("ds", CredentialField.API_KEY, "") is EnvPersistAction.REMOVED
    final = CredentialLoader(env_path)
    assert final.get_saved_var("DS_API_KEY") is None
    assert final.get_saved_var("DEEPSEEK_API_KEY") == "sk-deepseek-shared"


def test_duplicated_builtin_does_not_borrow_the_builtin_key(tmp_path: Path) -> None:
    """A copy of OpenAI, which may be pointed at another host, never reads ``OPENAI_API_KEY``.

    Args:
        tmp_path: Per-test temporary directory.
    """
    settings = tmp_path / "providers.json"
    instance = instance_from_preset_id("openai", instance_id="openai-copy")
    assert instance is not None
    _write_instances(settings, {"openai-copy": instance.to_mapping()})
    env_path = tmp_path / ".env"
    _ = env_path.write_text("OPENAI_API_KEY=sk-personal\n", encoding="utf-8")

    _ = ProviderSettingsStore(settings).load_instances()

    assert CredentialLoader(env_path).get_field("openai-copy", CredentialField.API_KEY) is None


def test_source_label_and_overview_cover_user_defined_instances(tmp_path: Path) -> None:
    """A custom instance's ``.env`` key is labelled as coming from ``.env`` and counted as configured.

    Args:
        tmp_path: Per-test temporary directory.
    """
    settings = tmp_path / "providers.json"
    _write_instances(settings, {"my-gw": ProviderInstance(instance_id="my-gw", api_base="https://gw.example/v1").to_mapping()})
    env_path = tmp_path / ".env"
    _ = env_path.write_text("MY_GW_API_KEY=sk-gateway\n", encoding="utf-8")
    _ = ProviderSettingsStore(settings).load_instances()
    loader = CredentialLoader(env_path)

    detector = CredentialSourceDetector(settings, env_path)

    assert detector.detect_source("my-gw", "sk-gateway") == CredentialSource.ENV_FILE
    assert "my-gw" in loader.list_configured_providers()


def test_connect_policy_reads_a_disabled_instance(tmp_path: Path) -> None:
    """An instance whose record says ``enabled: false`` is excluded from automatic connection.

    Args:
        tmp_path: Per-test temporary directory.
    """
    settings = tmp_path / "providers.json"
    disabled = ProviderInstance(instance_id="my-gw", api_base="https://gw.example/v1", enabled=False)
    enabled = ProviderInstance(instance_id="keyless", api_base="http://127.0.0.1:1/v1", requires_api_key=False)
    _write_instances(settings, {"my-gw": disabled.to_mapping(), "keyless": enabled.to_mapping()})

    policy = ProviderSettingsStore(settings).connect_policy()

    assert policy.is_enabled("my-gw") is False
    assert policy.is_enabled("keyless") is True
