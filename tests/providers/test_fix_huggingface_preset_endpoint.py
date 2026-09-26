# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The HuggingFace preset points at the Inference Providers router.

Hugging Face serves chat through ``https://router.huggingface.co`` (OpenAI
compatible under ``/v1``); the old ``api-inference.huggingface.co`` host is
deprecated. The preset's default base URL is what the settings page shows in
the base-URL field when nothing is saved, and saving the page writes that
field to ``HUGGINGFACE_API_BASE`` in ``.env`` -- so a stale preset value is
persisted and then used for every connection. These tests pin the preset,
the materialized instance and the value the settings page falls back to, to
the router the provider itself queries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from urllib.parse import urlsplit

from intellicrack.providers import ids as provider_ids
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.instances import instance_from_preset_id
from intellicrack.providers.presets import preset_for
from intellicrack.ui import provider_config


if TYPE_CHECKING:
    from collections.abc import Callable


_ROUTER_HOST = "router.huggingface.co"
_default_api_base = cast("Callable[[str], str]", getattr(provider_config, "_provider_default_api_base"))


def test_preset_default_is_the_router() -> None:
    """The preset names the router the provider queries, not the deprecated host."""
    preset = preset_for(provider_ids.HUGGINGFACE)

    assert preset is not None
    assert preset.default_api_base == HuggingFaceProvider.ROUTER_BASE_URL
    assert urlsplit(preset.default_api_base).hostname == _ROUTER_HOST


def test_materialized_instance_and_settings_fallback_use_the_router() -> None:
    """A materialized instance and the settings page's fallback both carry the router URL."""
    instance = instance_from_preset_id(provider_ids.HUGGINGFACE)

    assert instance is not None
    assert instance.api_base is not None
    assert urlsplit(instance.api_base).hostname == _ROUTER_HOST
    assert urlsplit(_default_api_base(provider_ids.HUGGINGFACE)).hostname == _ROUTER_HOST
