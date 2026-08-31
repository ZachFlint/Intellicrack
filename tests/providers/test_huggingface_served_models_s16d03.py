# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for HuggingFace served-model catalog filtering (S16-D03).

Before this fix, ``HuggingFaceProvider.list_models`` returned the raw Hub
text-generation catalog with no regard for which of those models the
configured token's HuggingFace Inference Providers actually serve for chat
completion. Requesting an unserved model produced an opaque HTTP 400
(``model_not_supported`` / an empty bad-request body) with no guidance.

These tests validate two independent, falsifiable properties of the fix:

* :meth:`~intellicrack.providers.huggingface.HuggingFaceProvider.list_models`
  only ever returns models present in the router's own served-model set
  (fetched live from ``GET https://router.huggingface.co/v1/models``), gated
  on a configured HuggingFace token so an unfunded/offline run skips cleanly
  instead of reporting a false failure.
* :meth:`~intellicrack.providers.huggingface.HuggingFaceProvider._validate_model_served`
  raises an actionable :class:`~intellicrack.core.types.ProviderError` -
  naming the requested model and mentioning "Inference Provider" - for a
  model absent from a cached served-model set. This half needs no live call:
  it constructs a real provider instance and exercises the pure validation
  logic directly.

The module-under-test's served-model cache and validation/parsing helpers
are protected members. Rather than accessing them through ``.`` attribute
syntax (which basedpyright's ``reportPrivateUsage`` rejects even inside
``tests/``), this file reads and calls them through ``vars(...)`` lookups,
mirroring the established pattern in ``test_realcov_11_huggingface_logic.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import httpx
import pytest

from intellicrack.core.types import ProviderError, ProviderName
from intellicrack.providers.huggingface import HuggingFaceProvider


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.credentials.env_loader import CredentialLoader


_OFFLINE_SKIP_REASON = "HuggingFace Hub unreachable (offline sandbox or no network)"
_UNSERVED_MODEL_ID = "intellicrack-test-org/definitely-not-a-served-model-s16d03"


def _get_served_model_ids(provider: HuggingFaceProvider) -> set[str] | None:
    """Read the provider's served-model cache via its instance ``__dict__``.

    Args:
        provider: The provider instance to inspect.

    Returns:
        set[str] | None: The cached served-model ID set, or ``None`` when
        no catalog has been fetched yet.
    """
    return cast("set[str] | None", vars(provider)["_served_model_ids"])


def _set_served_model_ids(provider: HuggingFaceProvider, served_ids: set[str] | None) -> None:
    """Populate the provider's served-model cache via its instance ``__dict__``.

    Args:
        provider: The provider instance to mutate.
        served_ids: The served-model ID set to cache, or ``None``.
    """
    vars(provider)["_served_model_ids"] = served_ids


def _validate_model_served(provider: HuggingFaceProvider, model: str) -> None:
    """Invoke the provider's model-served validator via the class ``__dict__``.

    A ``ProviderError`` raised by the underlying validator propagates to the
    caller unchanged.

    Args:
        provider: The provider instance to validate against.
        model: The requested model ID to validate.
    """
    fn = cast("Callable[[HuggingFaceProvider, str], None]", vars(HuggingFaceProvider)["_validate_model_served"])
    fn(provider, model)


def _parse_served_model_ids(payload: object) -> set[str]:
    """Invoke the router response parser via the class ``__dict__``.

    Args:
        payload: The decoded JSON response body to parse.

    Returns:
        set[str]: The parsed served-model ID set.
    """
    fn = cast("Callable[[object], set[str]]", vars(HuggingFaceProvider)["_parse_served_model_ids"])
    return fn(payload)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_list_models_only_returns_router_served_models(
    credential_loader: CredentialLoader,
    *,
    has_huggingface_key: bool,
) -> None:
    """``list_models`` never returns a model the router does not serve.

    Re-reads the served-model set that ``list_models`` cached from a live
    router response and asserts that every ID it returned is a member of it.
    This fails loudly if the intersection filter in
    :meth:`~intellicrack.providers.huggingface.HuggingFaceProvider.list_models`
    is ever removed or bypassed, since the unfiltered Hub catalog is known to
    include models tagged for text generation that no configured Inference
    Provider actually serves.

    Args:
        credential_loader: Loader providing the HuggingFace credentials.
        has_huggingface_key: True when a valid HuggingFace token is present.
    """
    if not has_huggingface_key:
        pytest.skip("HUGGINGFACE_API_TOKEN / HUGGINGFACE_TOKEN not configured")

    credentials = credential_loader.get_credentials(ProviderName.HUGGINGFACE)
    assert credentials is not None, "Expected credentials after validation"

    provider = HuggingFaceProvider()
    try:
        await provider.connect(credentials)
    except httpx.NetworkError:
        pytest.skip(_OFFLINE_SKIP_REASON)

    try:
        try:
            models = await provider.list_models()
        except httpx.NetworkError:
            pytest.skip(_OFFLINE_SKIP_REASON)

        assert len(models) > 0, "Expected at least one router-served model"

        served_ids = _get_served_model_ids(provider)
        assert served_ids is not None, "list_models() must populate the served-model cache"
        assert len(served_ids) > 0, "Router reported no served models for this token"

        unserved_returned = [model.id for model in models if model.id not in served_ids]
        assert not unserved_returned, f"list_models() returned models the router does not serve: {unserved_returned}"
    finally:
        await provider.disconnect()


class TestValidateModelServedRejectsUnservedModel:
    """Pure-logic coverage for the actionable unserved-model error path.

    No live HTTP call is made: a real :class:`HuggingFaceProvider` is
    constructed and its served-model cache is populated directly, exactly as
    :meth:`~intellicrack.providers.huggingface.HuggingFaceProvider.list_models`
    would populate it from a real router response. This isolates and
    falsifies the validation logic itself, independent of network
    availability.
    """

    @staticmethod
    def test_unserved_model_raises_actionable_provider_error() -> None:
        """An unserved model raises a ``ProviderError`` naming it and the cause."""
        provider = HuggingFaceProvider()
        _set_served_model_ids(provider, {"org/served-model-a", "org/served-model-b"})

        with pytest.raises(ProviderError) as exc_info:
            _validate_model_served(provider, _UNSERVED_MODEL_ID)

        message = str(exc_info.value)
        assert _UNSERVED_MODEL_ID in message, f"Error should name the rejected model, got: {message!r}"
        assert "Inference Provider" in message, f"Error should mention Inference Providers, got: {message!r}"

    @staticmethod
    def test_unserved_model_raises_exactly_provider_error_type() -> None:
        """The rejection's exact runtime type is ``ProviderError``, not a subclass or unrelated type.

        ``pytest.raises`` alone would also pass for a ``ProviderError``
        subclass raised by accident (e.g. ``AuthenticationError``), which
        would mask a routing bug in the validation method. Checking
        ``type(...) is ProviderError`` pins the exact contract instead.
        """
        provider = HuggingFaceProvider()
        _set_served_model_ids(provider, {"org/served-model-a"})

        with pytest.raises(ProviderError) as exc_info:
            _validate_model_served(provider, _UNSERVED_MODEL_ID)

        assert type(exc_info.value) is ProviderError

    @staticmethod
    def test_served_model_does_not_raise() -> None:
        """A model present in the cached served set passes validation silently."""
        provider = HuggingFaceProvider()
        _set_served_model_ids(provider, {"org/served-model-a", "org/served-model-b"})

        _validate_model_served(provider, "org/served-model-a")

    @staticmethod
    def test_policy_suffixed_served_model_does_not_raise() -> None:
        """A ``:policy``-suffixed model ID is matched against its base model ID."""
        provider = HuggingFaceProvider()
        _set_served_model_ids(provider, {"org/served-model-a"})

        _validate_model_served(provider, "org/served-model-a:cheapest")

    @staticmethod
    def test_validation_is_skipped_when_no_catalog_cached() -> None:
        """With no served-model cache populated yet, validation is a no-op.

        A provider that has not called ``list_models()`` in this session
        must not block a caller who already knows a valid model ID.
        """
        provider = HuggingFaceProvider()
        assert _get_served_model_ids(provider) is None

        _validate_model_served(provider, _UNSERVED_MODEL_ID)

    @staticmethod
    @pytest.mark.asyncio
    async def test_disconnect_clears_served_model_cache() -> None:
        """``disconnect`` resets the served-model cache to unset.

        Regression guard: a stale cache surviving a disconnect/reconnect
        cycle would either wrongly reject a newly-served model or wrongly
        accept a model that stopped being served.
        """
        provider = HuggingFaceProvider()
        _set_served_model_ids(provider, {"org/served-model-a"})
        assert _get_served_model_ids(provider) is not None

        await provider.disconnect()

        assert _get_served_model_ids(provider) is None
        _validate_model_served(provider, _UNSERVED_MODEL_ID)


class TestParseServedModelIds:
    """Validate the router response parser over real JSON-shaped payloads."""

    @staticmethod
    def test_parses_well_formed_openai_style_payload() -> None:
        """A well-formed OpenAI-style ``/v1/models`` payload yields its IDs."""
        payload = {
            "object": "list",
            "data": [
                {"id": "org/model-a", "object": "model"},
                {"id": "org/model-b", "object": "model"},
            ],
        }
        assert _parse_served_model_ids(payload) == {"org/model-a", "org/model-b"}

    @staticmethod
    def test_skips_malformed_entries_without_raising() -> None:
        """Malformed entries are skipped rather than raising or dropping the rest."""
        payload = {
            "data": [
                {"id": "org/valid-model"},
                {"id": ""},
                {"no_id_field": True},
                "not-a-dict",
                {"id": 12345},
            ],
        }
        assert _parse_served_model_ids(payload) == {"org/valid-model"}

    @staticmethod
    def test_non_dict_payload_yields_empty_set() -> None:
        """A non-dict top-level payload yields an empty set instead of raising."""
        assert _parse_served_model_ids([1, 2, 3]) == set()

    @staticmethod
    def test_missing_data_key_yields_empty_set() -> None:
        """A payload without a ``data`` list yields an empty set."""
        assert _parse_served_model_ids({"object": "list"}) == set()
