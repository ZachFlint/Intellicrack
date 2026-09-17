# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A configured provider endpoint, and the transport policy that guards it.

A :class:`ProviderInstance` is everything Intellicrack needs to talk to one
endpoint that is not baked into the code: its id, the wire format it speaks,
where it lives, what headers it wants, what body parameters to add or drop,
and what its models can do. Built-in providers are instances too, materialized
from their presets, which is what lets a user duplicate OpenAI for a second
account or pin it at a proxy.

Secrets are deliberately absent. An instance record is written to
``providers.json`` and can be exported and shared; the key lives in the OS
keyring under the instance id, with ``<INSTANCE_ID>_API_KEY`` in ``.env`` as an
override.

The transport policy is the one place this module says no, and it says it
quietly. ``https://`` anywhere is fine. ``http://`` to loopback or a private
range is fine and silent, because the Ollama, LM Studio and vLLM case must
have no friction. ``http://`` to a public host is the only case that asks: it
requires one explicit, persisted acknowledgement before the key is attached,
and it warns rather than blocks, because a legitimate internal gateway that
resolves through public DNS would otherwise be unusable.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlsplit

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride
from intellicrack.providers.dialects.base import ToolNameStyle, headers_receiving_api_key
from intellicrack.providers.ids import api_key_env_var, normalize_provider_id
from intellicrack.providers.presets import ProviderPreset, preset_for


_logger = get_logger(__name__)

LOCAL_HOST_SUFFIXES: Final[tuple[str, ...]] = (".localhost", ".local", ".internal", ".home.arpa")
"""Host suffixes treated as local for the plaintext-transport rule."""

LOCAL_HOST_NAMES: Final[frozenset[str]] = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})
"""Host names treated as local for the plaintext-transport rule."""


class TransportRisk(enum.Enum):
    """How exposed an endpoint's transport is.

    Attributes:
        SECURE: TLS, or a scheme that carries no credential at all.
        LOCAL_PLAINTEXT: Plain HTTP to loopback or a private range. Allowed
            silently: this is the local-runtime case.
        PUBLIC_PLAINTEXT: Plain HTTP to a host that is neither loopback nor
            private. Requires an explicit acknowledgement before the API key
            is attached.
    """

    SECURE = "secure"
    LOCAL_PLAINTEXT = "local-plaintext"
    PUBLIC_PLAINTEXT = "public-plaintext"


def classify_transport(api_base: str | None) -> TransportRisk:
    """Classify how exposed an endpoint's transport is.

    Args:
        api_base: The instance's base URL, or ``None`` when the SDK default
            applies. A missing base URL is treated as secure, because the
            defaults it stands in for are all HTTPS.

    Returns:
        TransportRisk: The transport's exposure.
    """
    if not api_base:
        return TransportRisk.SECURE
    parts = urlsplit(api_base.strip())
    if parts.scheme.lower() != "http":
        return TransportRisk.SECURE
    host = (parts.hostname or "").lower()
    if not host:
        return TransportRisk.SECURE
    if host in LOCAL_HOST_NAMES or host.endswith(LOCAL_HOST_SUFFIXES):
        return TransportRisk.LOCAL_PLAINTEXT
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return TransportRisk.PUBLIC_PLAINTEXT
    if address.is_loopback or address.is_private or address.is_link_local:
        return TransportRisk.LOCAL_PLAINTEXT
    return TransportRisk.PUBLIC_PLAINTEXT


@dataclass
class ProviderInstance:
    """One configured provider endpoint.

    Attributes:
        instance_id: The id this instance is registered and keyed under.
        display_name: Human-readable label shown in the UI.
        preset_id: The preset this instance was created from, or ``None`` for
            one configured entirely by hand. It supplies the capability
            defaults and the endpoint's known model families.
        dialect: The wire format this endpoint speaks.
        api_base: Base URL, or ``None`` to use the preset's default.
        headers: Extra request headers. A value containing ``${apiKey}``
            receives the instance's key at request time, and a header that
            carries a credential suppresses the adapter's inferred one.
        extra_body: Body parameters merged into every request last.
        drop_params: Top-level request keys removed before sending, for a
            gateway that rejects a parameter the dialect normally includes.
        tool_name_style: How canonical dotted tool names are written.
        store_responses: Whether the endpoint may retain requests server-side.
            ``False`` is the default on Responses, so multi-turn reasoning
            still works through encrypted reasoning content without the
            endpoint retaining binary-analysis context.
        requires_api_key: Whether the endpoint refuses unauthenticated
            requests.
        timeout_seconds: Request timeout override, or ``None`` for the
            default.
        enabled: Whether this instance is connected automatically at startup.
        default_model: Model selected by default in the UI.
        model_overrides: Per-model capability overrides, the top layer of the
            capability merge.
        insecure_transport_acknowledged: Whether the user has explicitly
            accepted sending this instance's key over plain HTTP to a public
            host.
    """

    instance_id: str
    display_name: str = ""
    preset_id: str | None = None
    dialect: ApiDialect = ApiDialect.CHAT_COMPLETIONS
    api_base: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    extra_body: dict[str, Any] = field(default_factory=dict)
    drop_params: frozenset[str] = frozenset()
    tool_name_style: ToolNameStyle = ToolNameStyle.DOUBLE_UNDERSCORE
    store_responses: bool = False
    requires_api_key: bool = True
    timeout_seconds: float | None = None
    enabled: bool = True
    default_model: str = ""
    model_overrides: dict[str, CapabilityOverride] = field(default_factory=dict)
    insecure_transport_acknowledged: bool = False

    @property
    def api_key_env_var(self) -> str:
        """The environment variable that overrides this instance's stored key.

        Returns:
            str: ``<INSTANCE_ID>_API_KEY``, upper-snake, following Zed.
        """
        return api_key_env_var(self.instance_id)

    @property
    def transport_risk(self) -> TransportRisk:
        """How exposed this instance's transport is.

        Returns:
            TransportRisk: The transport's exposure.
        """
        return classify_transport(self.api_base)

    def may_send_api_key(self) -> bool:
        """Report whether this instance's key may be attached to a request.

        Returns:
            bool: ``False`` only when the endpoint is plain HTTP to a public
            host and the user has not acknowledged that. Everything else,
            including plain HTTP to a local runtime, is allowed.
        """
        if self.transport_risk is not TransportRisk.PUBLIC_PLAINTEXT:
            return True
        return self.insecure_transport_acknowledged

    def headers_carrying_api_key(self) -> tuple[str, ...]:
        """Name every configured header that will receive the API key.

        The settings UI shows this before a save so the user always knows
        exactly where their credential is about to be sent.

        Returns:
            tuple[str, ...]: Header names carrying the ``${apiKey}``
            placeholder, in configuration order.
        """
        return headers_receiving_api_key(self.headers)

    def label(self) -> str:
        """The label to show for this instance.

        Returns:
            str: The configured display name, falling back to the id.
        """
        return self.display_name or self.instance_id

    def to_mapping(self) -> dict[str, Any]:
        """Serialize this instance for ``providers.json``.

        The result never contains a secret, so it is safe to export and share.

        Returns:
            dict[str, Any]: JSON-compatible record.
        """
        return {
            "instance_id": self.instance_id,
            "display_name": self.display_name,
            "preset_id": self.preset_id,
            "dialect": self.dialect.value,
            "api_base": self.api_base,
            "headers": dict(self.headers),
            "extra_body": dict(self.extra_body),
            "drop_params": sorted(self.drop_params),
            "tool_name_style": self.tool_name_style.value,
            "store_responses": self.store_responses,
            "requires_api_key": self.requires_api_key,
            "timeout_seconds": self.timeout_seconds,
            "enabled": self.enabled,
            "default_model": self.default_model,
            "model_overrides": {model: override.to_mapping() for model, override in self.model_overrides.items()},
            "insecure_transport_acknowledged": self.insecure_transport_acknowledged,
        }

    @classmethod
    def from_mapping(cls, record: dict[str, Any]) -> ProviderInstance | None:
        """Rebuild an instance from its ``providers.json`` representation.

        Args:
            record: A mapping previously produced by :meth:`to_mapping`, or
                imported from another installation.

        Returns:
            ProviderInstance | None: The reconstructed instance, or ``None``
            when the record names no valid instance id.
        """
        raw_id = record.get("instance_id")
        if not isinstance(raw_id, str):
            return None
        try:
            instance_id = normalize_provider_id(raw_id)
        except ValueError:
            _logger.warning("provider_instance_id_invalid", instance_id=raw_id)
            return None

        dialect = _coerce_dialect(record.get("dialect"))
        style = _coerce_name_style(record.get("tool_name_style"))
        overrides: dict[str, CapabilityOverride] = {}
        raw_overrides = record.get("model_overrides")
        if is_json_object(raw_overrides):
            for model, entry in raw_overrides.items():
                if is_json_object(entry):
                    overrides[str(model)] = CapabilityOverride.from_mapping(entry)

        return cls(
            instance_id=instance_id,
            display_name=_as_str(record.get("display_name")),
            preset_id=_as_optional_str(record.get("preset_id")),
            dialect=dialect,
            api_base=_as_optional_str(record.get("api_base")),
            headers=_as_str_mapping(record.get("headers")),
            extra_body=_as_mapping(record.get("extra_body")),
            drop_params=frozenset(_as_str_list(record.get("drop_params"))),
            tool_name_style=style,
            store_responses=bool(record.get("store_responses")),
            requires_api_key=bool(record.get("requires_api_key", True)),
            timeout_seconds=_as_optional_float(record.get("timeout_seconds")),
            enabled=bool(record.get("enabled", True)),
            default_model=_as_str(record.get("default_model")),
            model_overrides=overrides,
            insecure_transport_acknowledged=bool(record.get("insecure_transport_acknowledged")),
        )

    @classmethod
    def from_preset(cls, preset: ProviderPreset, *, instance_id: str | None = None) -> ProviderInstance:
        """Materialize a preset into an editable instance.

        This is how a built-in provider becomes an ordinary instance: one
        mechanism for built-ins and user endpoints alike, so a built-in can be
        duplicated or pinned at a proxy, and deleting one restores it from its
        preset rather than orphaning it.

        Args:
            preset: The preset to materialize.
            instance_id: The id for the new instance, defaulting to the
                preset's own provider id.

        Returns:
            ProviderInstance: The materialized instance.
        """
        resolved_id = normalize_provider_id(instance_id or preset.provider_id)
        return cls(
            instance_id=resolved_id,
            display_name=preset.display_name,
            preset_id=preset.provider_id,
            dialect=preset.dialect if preset.dialect is not None else ApiDialect.CHAT_COMPLETIONS,
            api_base=preset.default_api_base,
            requires_api_key=preset.requires_api_key,
        )


def instance_from_preset_id(preset_id: str, *, instance_id: str | None = None) -> ProviderInstance | None:
    """Materialize a preset by id.

    Args:
        preset_id: The preset to materialize.
        instance_id: The id for the new instance, defaulting to the preset's.

    Returns:
        ProviderInstance | None: The materialized instance, or ``None`` when
        no preset matches.
    """
    preset = preset_for(preset_id)
    if preset is None:
        _logger.warning("provider_instance_preset_unknown", preset_id=preset_id)
        return None
    return ProviderInstance.from_preset(preset, instance_id=instance_id)


def _coerce_dialect(raw: object) -> ApiDialect:
    """Coerce a stored dialect value back to its enum member.

    Args:
        raw: The stored value.

    Returns:
        ApiDialect: The matching member, defaulting to Chat Completions, which
        is what an unknown endpoint is assumed to speak.
    """
    if isinstance(raw, ApiDialect):
        return raw
    if isinstance(raw, str):
        for member in ApiDialect:
            if member.value == raw:
                return member
        _logger.warning("provider_instance_dialect_unknown", dialect=raw)
    return ApiDialect.CHAT_COMPLETIONS


def _coerce_name_style(raw: object) -> ToolNameStyle:
    """Coerce a stored tool-name style back to its enum member.

    Args:
        raw: The stored value.

    Returns:
        ToolNameStyle: The matching member, defaulting to the ``__`` mapping.
    """
    if isinstance(raw, ToolNameStyle):
        return raw
    if isinstance(raw, str):
        for member in ToolNameStyle:
            if member.value == raw:
                return member
    return ToolNameStyle.DOUBLE_UNDERSCORE


def _as_str(raw: object) -> str:
    """Coerce a stored value to a string.

    Args:
        raw: The stored value.

    Returns:
        str: The value when it is a string, otherwise the empty string.
    """
    return raw if isinstance(raw, str) else ""


def _as_optional_str(raw: object) -> str | None:
    """Coerce a stored value to a non-empty string or ``None``.

    Args:
        raw: The stored value.

    Returns:
        str | None: The stripped string when non-empty, otherwise ``None``.
    """
    if isinstance(raw, str):
        stripped = raw.strip()
        return stripped or None
    return None


def _as_optional_float(raw: object) -> float | None:
    """Coerce a stored value to a positive float or ``None``.

    Args:
        raw: The stored value.

    Returns:
        float | None: The coerced value, or ``None`` when absent or unusable.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw) if raw > 0 else None
    if isinstance(raw, str):
        try:
            value = float(raw)
        except ValueError:
            return None
        return value if value > 0 else None
    return None


def _as_str_mapping(raw: object) -> dict[str, str]:
    """Coerce a stored value to a string-to-string mapping.

    Args:
        raw: The stored value.

    Returns:
        dict[str, str]: Entries whose key and value are both strings.
    """
    if not is_json_object(raw):
        return {}
    mapping: dict[str, Any] = raw
    return {str(key): value for key, value in mapping.items() if isinstance(value, str)}


def _as_mapping(raw: object) -> dict[str, Any]:
    """Coerce a stored value to a JSON object.

    Args:
        raw: The stored value.

    Returns:
        dict[str, Any]: The mapping, or an empty one.
    """
    if not is_json_object(raw):
        return {}
    mapping: dict[str, Any] = raw
    return dict(mapping)


def _as_str_list(raw: object) -> list[str]:
    """Coerce a stored value to a list of strings.

    Args:
        raw: The stored value.

    Returns:
        list[str]: The string entries, or an empty list.
    """
    if not is_json_array(raw):
        return []
    entries: list[Any] = raw
    return [str(entry) for entry in entries]
