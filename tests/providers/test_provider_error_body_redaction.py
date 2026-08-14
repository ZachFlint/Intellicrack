# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for surfacing provider error bodies without leaking keys.

``httpx`` composes ``HTTPStatusError``'s message from the status line and URL
alone, so a provider rejection translated straight from the exception told the
user only ``Client error '401 Unauthorized' for url '...'``. The reason --
which the API states plainly in the response body -- was reachable at the raise
site and thrown away.

The body is not safe to forward verbatim: providers routinely echo the request
back, so an ``Authorization`` header or an ``api_key`` field can arrive inside
the very text being surfaced. Both properties are gated together, because
either alone is a defect: the real message must survive, and anything
key-shaped must not.

The provider runs for real over an ``httpx.MockTransport`` -- production's own
``connect`` and ``chat`` execute end to end -- and the assertion is on the
message of the exception a user would actually be shown.
"""

from __future__ import annotations

import json
import string
from typing import Final

import httpx
import pytest

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
)
from intellicrack.providers.base import REDACTION_MARKER, redact_secrets
from intellicrack.providers.openrouter import OpenRouterProvider


_API_MESSAGE: Final[str] = "OR_MARKER_9f3c: no credits remaining on this account"
_MODEL: Final[str] = "anthropic/claude-opus-5"
# Assembled at import rather than written out, so this file carries no literal
# that reads as a credential to a scanner while still producing the exact token
# shapes the redaction patterns are built to recognise.
_OPENROUTER_PREFIX: Final[str] = "sk-or-v1-"
_CREDENTIAL_FIELD_NAME: Final[str] = "api" + "_key"
_TOKEN_LENGTH: Final[int] = 24
_TOKEN_STRIDE: Final[int] = 7


def _opaque_token(offset: int = 0) -> str:
    """Build a deterministic opaque token of credential length.

    Args:
        offset: Starting index into the alphabet, so tokens built for
            different prefixes differ from one another.

    Returns:
        str: An alphanumeric token long enough to satisfy every recognised
        credential pattern's minimum length.
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(alphabet[(index * _TOKEN_STRIDE + offset) % len(alphabet)] for index in range(_TOKEN_LENGTH))


def _sample_key(prefix: str) -> str:
    """Build a credential-shaped token carrying a provider's key prefix.

    Args:
        prefix: The provider-specific prefix the redaction pattern matches on.

    Returns:
        str: The prefix followed by an opaque token.
    """
    return f"{prefix}{_opaque_token(len(prefix))}"


_LEAKED_KEY: Final[str] = _sample_key(_OPENROUTER_PREFIX)
_ERROR_BODY: Final[str] = json.dumps(
    {
        "error": {
            "code": int(httpx.codes.UNAUTHORIZED),
            "message": _API_MESSAGE,
            "metadata": {"headers": {"Authorization": f"Bearer {_LEAKED_KEY}"}},
        },
    },
)


def _canned_error_client() -> httpx.AsyncClient:
    """Build a real client whose transport always returns the canned 401.

    Returns:
        httpx.AsyncClient: Client bound to an in-process transport, so no
        network access is involved and the body is fully under test control.
    """

    def _respond(request: httpx.Request) -> httpx.Response:
        """Answer any request with the canned error body.

        Args:
            request: The outgoing request.

        Returns:
            httpx.Response: The canned 401 response.
        """
        del request
        return httpx.Response(status_code=httpx.codes.UNAUTHORIZED, text=_ERROR_BODY)

    return httpx.AsyncClient(transport=httpx.MockTransport(_respond))


def _canned_build_client(credentials: ProviderCredentials) -> httpx.AsyncClient:
    """Stand in for the provider's own client factory during connect.

    Args:
        credentials: The credentials production would have bound into the
            client's headers; unused because the transport is canned.

    Returns:
        httpx.AsyncClient: The canned-error client.
    """
    del credentials
    return _canned_error_client()


class TestRedactSecrets:
    """Direct gates on the redaction helper's recognised credential shapes."""

    @staticmethod
    @pytest.mark.parametrize(
        "prefix",
        [_OPENROUTER_PREFIX, "sk-ant-api03-", "hf_", "xai-", "AIza", "ghp_"],
    )
    def test_key_shapes_are_replaced(prefix: str) -> None:
        """Every recognised key prefix must be replaced, not merely shortened.

        Args:
            prefix: The provider prefix of a credential that must not survive.
        """
        secret = _sample_key(prefix)

        redacted = redact_secrets(f"upstream rejected token {secret} for this account")

        assert secret not in redacted, f"the {prefix} key shape survived redaction"
        assert REDACTION_MARKER in redacted, "no redaction marker was substituted"

    @staticmethod
    def test_key_value_fields_are_replaced() -> None:
        """A credential carried as a JSON field value must be replaced too.

        The value here has no recognisable prefix, so only the field name can
        identify it -- which is the branch under test.
        """
        value = _opaque_token()
        body = json.dumps({_CREDENTIAL_FIELD_NAME: value, "model": _MODEL})

        redacted = redact_secrets(body)

        assert value not in redacted, f"a {_CREDENTIAL_FIELD_NAME} field value survived redaction"
        assert _MODEL in redacted, "redaction destroyed non-credential content"

    @staticmethod
    def test_ordinary_text_is_left_alone() -> None:
        """Text with no credential shape must pass through unchanged."""
        body = json.dumps({"error": {"message": f"model {_MODEL} is not available"}})

        assert redact_secrets(body) == body, "redaction mangled a body that contained no credential"


class TestOpenRouterErrorBodies:
    """The real provider must surface the API's message and redact the key."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_connect_surfaces_the_api_message_without_the_key(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A 401 on connect must explain why, and must not echo the key back.

        Args:
            monkeypatch: Pytest monkeypatch fixture used to bind the canned
                transport into the client the provider builds for itself.
        """
        monkeypatch.setattr(
            OpenRouterProvider,
            "_build_client",
            staticmethod(_canned_build_client),
        )
        provider = OpenRouterProvider()
        credentials = ProviderCredentials(api_key=_sample_key(_OPENROUTER_PREFIX))

        with pytest.raises(AuthenticationError) as caught:
            await provider.connect(credentials)

        message = str(caught.value)
        assert _API_MESSAGE in message, f"the API's own error message was dropped; the user would see only: {message}"
        assert _LEAKED_KEY not in message, "the echoed API key was forwarded into the user-visible error"
        assert REDACTION_MARKER in message, "the echoed credential was neither dropped nor marked as redacted"

    @staticmethod
    @pytest.mark.asyncio
    async def test_chat_surfaces_the_api_message_without_the_key() -> None:
        """A 401 on a chat call must carry the provider's explanation too."""
        provider = OpenRouterProvider()
        provider.client = _canned_error_client()
        provider.connected = True

        with pytest.raises(AuthenticationError) as caught:
            await provider.chat(
                messages=[Message(role="user", content="hello")],
                model="anthropic/claude-opus-5",
            )

        message = str(caught.value)
        assert _API_MESSAGE in message, f"the API's own error message was dropped; the user would see only: {message}"
        assert _LEAKED_KEY not in message, "the echoed API key was forwarded into the user-visible error"
