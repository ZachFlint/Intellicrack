# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Keyring-backed resolution of ``${input:id}`` references in MCP configuration.

``mcp.json`` never holds a credential. Wherever one is needed it carries a ``${input:<id>}`` reference, and this module exchanges that
reference for the real value held in the operating system keyring under a per-input key.

Resolution is strict in both directions that matter. A reference with no stored value raises rather than expanding to an empty string,
because an empty API key reaches the server as an anonymous request and produces a confusing authorization failure instead of an actionable
one. An unusable keyring likewise raises, so a server never starts unauthenticated.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.store import CredentialStoreError, KeyringUnavailableError
from intellicrack.mcp.config import INPUT_REFERENCE_PATTERN, NAMESPACE_PREFIX, referenced_input_ids
from intellicrack.mcp.errors import McpAuthError, McpConfigError


if TYPE_CHECKING:
    import re
    from collections.abc import Mapping, Sequence

    from intellicrack.credentials.store import CredentialStore


_logger = get_logger(__name__)


MCP_SECRET_NAMESPACE: Final[str] = NAMESPACE_PREFIX.removesuffix("-")
"""Prefix of every credential-store key this module owns.

Derived from the tool-namespace prefix so a server's tools and its stored inputs are always filed under the same identifier.
"""

_INPUT_KEY_TEMPLATE: Final[str] = MCP_SECRET_NAMESPACE + ":input:{input_id}"


def input_credential_key(input_id: str) -> str:
    """Build the credential-store key one input's value is held under.

    Args:
        input_id: The input declaration's identifier.

    Returns:
        str: The provider key, e.g. ``mcp:input:gh-token``.
    """
    return _INPUT_KEY_TEMPLATE.format(input_id=input_id)


class McpSecretResolver:
    """Expands ``${input:id}`` references from the credential store.

    One resolver serves every configured server. Values are read on demand rather than cached, so a credential rotated in the keyring takes
    effect on the next connection without restarting the application.
    """

    def __init__(self, store: CredentialStore) -> None:
        """Initialize the resolver.

        Args:
            store: Credential store holding each input's value.
        """
        self._store = store

    @property
    def store(self) -> CredentialStore:
        """The credential store this resolver reads and writes.

        Returns:
            CredentialStore: The backing store.
        """
        return self._store

    async def resolve(self, template: str) -> str:
        """Expand every ``${input:id}`` reference in one configuration value.

        Args:
            template: The raw configuration value.

        Returns:
            str: ``template`` with each reference replaced by its stored
            value. A value carrying no reference is returned unchanged
            without touching the keyring.

        A referenced input with no stored value propagates
        :class:`McpConfigError`, and an unusable keyring propagates
        :class:`McpAuthError`, both from :meth:`resolve_input`.
        """
        references = referenced_input_ids(template)
        if not references:
            return template
        resolved: dict[str, str] = {}
        for input_id in references:
            if input_id in resolved:
                continue
            resolved[input_id] = await self._read_input(input_id)

        def _expand(match: re.Match[str]) -> str:
            """Replace one matched reference with its resolved value.

            Args:
                match: The matched ``${input:id}`` reference.

            Returns:
                str: The stored value for the referenced input.
            """
            return resolved[match.group(1)]

        return INPUT_REFERENCE_PATTERN.sub(_expand, template)

    async def resolve_mapping(self, values: Mapping[str, str]) -> dict[str, str]:
        """Expand references across a whole environment or header mapping.

        Args:
            values: Raw configuration values keyed by field name.

        Returns:
            dict[str, str]: The same keys with every value expanded.

        Raises:
            McpConfigError: If a referenced input has no stored value. The
                message names the field so the operator knows which entry to
                fix.
        """
        expanded: dict[str, str] = {}
        for name, value in values.items():
            try:
                expanded[name] = await self.resolve(value)
            except McpConfigError as exc:
                message = f"{name}: {exc.message}"
                raise McpConfigError(message) from exc
        return expanded

    async def resolve_sequence(self, values: Sequence[str], *, field: str) -> tuple[str, ...]:
        """Expand references across an ordered list such as launch arguments.

        Args:
            values: Raw configuration values, in order.
            field: Name of the list, used in the error message.

        Returns:
            tuple[str, ...]: The same values, in order, each expanded.

        Raises:
            McpConfigError: If a referenced input has no stored value. The
                message names the position so the operator knows which entry
                to fix.
        """
        expanded: list[str] = []
        for index, value in enumerate(values):
            try:
                expanded.append(await self.resolve(value))
            except McpConfigError as exc:
                message = f"{field}[{index}]: {exc.message}"
                raise McpConfigError(message) from exc
        return tuple(expanded)

    async def set_input(self, input_id: str, value: str) -> None:
        """Store one input's value in the keyring.

        Args:
            input_id: The input declaration's identifier.
            value: The value to store.

        Raises:
            McpAuthError: If the keyring is unusable, so nothing was stored.
        """
        key = input_credential_key(input_id)
        try:
            await self._store.set(key, ProviderCredentials(api_key=value), key_name=f"MCP input {input_id}")
        except KeyringUnavailableError as exc:
            message = f"cannot store MCP input {input_id!r}: {exc}"
            raise McpAuthError(message) from exc
        except CredentialStoreError as exc:
            message = f"cannot store MCP input {input_id!r}: the keyring refused the value ({exc}). Nothing was stored."
            raise McpAuthError(message) from exc
        _logger.info("mcp_input_stored", input_id=input_id)

    async def delete_input(self, input_id: str) -> bool:
        """Remove one input's stored value.

        Args:
            input_id: The input declaration's identifier.

        Returns:
            bool: ``True`` when a value was removed, ``False`` when none was
            stored.

        Raises:
            McpAuthError: If the keyring is unusable, so nothing could be
                removed.
        """
        key = input_credential_key(input_id)
        try:
            removed = await self._store.delete(key)
        except CredentialStoreError as exc:
            message = f"cannot remove MCP input {input_id!r}: {exc}"
            raise McpAuthError(message) from exc
        _logger.info("mcp_input_deleted", input_id=input_id, removed=removed)
        return removed

    async def has_input(self, input_id: str) -> bool:
        """Report whether an input currently has a stored value.

        Args:
            input_id: The input declaration's identifier.

        Returns:
            bool: ``True`` when a non-empty value is stored.

        Raises:
            McpAuthError: If the keyring is unusable, so the answer is
                unknown. An unknown answer is never reported as ``False``,
                which would let a caller conclude the operator simply has
                not entered the value yet.
        """
        try:
            credentials = await self._store.get_secret(input_credential_key(input_id))
        except CredentialStoreError as exc:
            message = f"cannot read MCP input {input_id!r}: {exc}"
            raise McpAuthError(message) from exc
        return credentials is not None and bool(credentials.api_key)

    async def _read_input(self, input_id: str) -> str:
        """Read one input's value, refusing to substitute an empty string.

        Args:
            input_id: The input declaration's identifier.

        Returns:
            str: The stored value.

        Raises:
            McpConfigError: If no value is stored for the input.
            McpAuthError: If the keyring is unusable.
        """
        try:
            credentials = await self._store.get_secret(input_credential_key(input_id))
        except CredentialStoreError as exc:
            message = f"cannot read MCP input {input_id!r} from the keyring: {exc}. The server will not be started without it."
            raise McpAuthError(message) from exc
        if credentials is None or not credentials.api_key:
            message = (
                f"no value stored for MCP input {input_id!r}. Enter it in MCP Settings so the reference "
                f"${{input:{input_id}}} can be resolved."
            )
            raise McpConfigError(message)
        return credentials.api_key
