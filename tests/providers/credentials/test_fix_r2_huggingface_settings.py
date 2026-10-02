# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 27: HuggingFace base URLs saved for the retired inference host are migrated, and the default URL is never saved.

The gates run the real credential loader over real ``.env`` files in a temporary directory, and the real settings panel over them. A
``HUGGINGFACE_API_BASE`` naming ``api-inference.huggingface.co`` is removed from the file when it is loaded, so the provider uses the router,
while every other line is kept; saving the router URL writes nothing, since it is what the provider uses anyway.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QLineEdit

from intellicrack.credentials.env_loader import CredentialField, CredentialLoader, EnvPersistAction
from intellicrack.providers import ids as provider_ids
from intellicrack.ui.provider_config import ProviderSettingsWidget


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


_ROUTER: Final[str] = "https://router.huggingface.co"
_TOKEN_LINE: Final[str] = "HUGGINGFACE_API_TOKEN=hf_loopbackToken0123456789"
_OTHER_LINE: Final[str] = "OPENAI_API_BASE=https://gateway.example/v1"


@pytest.mark.parametrize(
    "retired",
    ["https://api-inference.huggingface.co", "https://api-inference.huggingface.co/models", "https://API-INFERENCE.huggingface.co/"],
)
def test_retired_inference_host_is_migrated_on_load(tmp_path: Path, retired: str) -> None:
    """A base URL on the retired host is removed from ``.env`` and from the credentials, and nothing else changes.

    Args:
        tmp_path: Per-test directory.
        retired: The saved base URL.
    """
    env_path = tmp_path / ".env"
    _ = env_path.write_text(f"{_TOKEN_LINE}\nHUGGINGFACE_API_BASE={retired}\n{_OTHER_LINE}\n", encoding="utf-8")

    loader = CredentialLoader(env_path=env_path)
    credentials = loader.get_credentials(provider_ids.HUGGINGFACE)

    assert credentials is not None
    assert credentials.api_base is None
    assert loader.get_field(provider_ids.HUGGINGFACE, CredentialField.API_BASE) is None
    assert env_path.read_text(encoding="utf-8").splitlines() == [_TOKEN_LINE, _OTHER_LINE]
    assert CredentialLoader(env_path=env_path).get_saved_var("HUGGINGFACE_API_BASE") is None


def test_a_custom_huggingface_endpoint_is_kept(tmp_path: Path) -> None:
    """A base URL on any other host, such as a dedicated Inference Endpoint, is left as saved.

    Args:
        tmp_path: Per-test directory.
    """
    endpoint = "https://xyz123.us-east-1.aws.endpoints.huggingface.cloud"
    env_path = tmp_path / ".env"
    _ = env_path.write_text(f"{_TOKEN_LINE}\nHUGGINGFACE_API_BASE={endpoint}\n", encoding="utf-8")

    credentials = CredentialLoader(env_path=env_path).get_credentials(provider_ids.HUGGINGFACE)

    assert credentials is not None
    assert credentials.api_base == endpoint
    assert f"HUGGINGFACE_API_BASE={endpoint}" in env_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("entered", [_ROUTER, f"{_ROUTER}/", f"  {_ROUTER}  "])
def test_saving_the_router_url_writes_nothing(tmp_path: Path, entered: str) -> None:
    """Persisting the router URL, which is the default, leaves ``.env`` without a HuggingFace base URL.

    Args:
        tmp_path: Per-test directory.
        entered: What the operator typed.
    """
    env_path = tmp_path / ".env"
    _ = env_path.write_text(f"{_TOKEN_LINE}\n", encoding="utf-8")
    loader = CredentialLoader(env_path=env_path)

    action = loader.persist_field(provider_ids.HUGGINGFACE, CredentialField.API_BASE, entered)

    assert action is EnvPersistAction.UNCHANGED
    assert "HUGGINGFACE_API_BASE" not in env_path.read_text(encoding="utf-8")


def test_settings_panel_does_not_write_the_default_url(qtbot: QtBot, tmp_path: Path) -> None:
    """Saving the HuggingFace panel with the router URL typed in keeps it out of ``.env``.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
    """
    env_path = tmp_path / ".env"
    _ = env_path.write_text(f"{_TOKEN_LINE}\n", encoding="utf-8")
    widget = ProviderSettingsWidget(
        provider_id=provider_ids.HUGGINGFACE,
        config_path=tmp_path / "providers.json",
        credential_loader=CredentialLoader(env_path=env_path),
    )
    qtbot.addWidget(widget)
    base_inputs = [edit for edit in widget.findChildren(QLineEdit) if edit.placeholderText() == _ROUTER]
    assert len(base_inputs) == 1, "the base URL field should show the router as its default"
    base_inputs[0].setText(_ROUTER)
    widget.save_settings()

    assert "HUGGINGFACE_API_BASE" not in env_path.read_text(encoding="utf-8")
