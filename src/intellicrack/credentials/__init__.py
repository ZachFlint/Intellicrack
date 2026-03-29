# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Credential management for Intellicrack.

This module handles loading and validating API credentials from multiple sources:
- .env files (via CredentialLoader)
- OS keyring (via CredentialStore)
- OAuth 2.0 flows (via OAuthManager)
"""

from __future__ import annotations

from .env_loader import (
    CredentialLoader,
    ProviderCredentialMapping,
    get_credential_loader,
)
from .oauth import (
    OAuthAuthorizationError,
    OAuthCallbackError,
    OAuthConfig,
    OAuthConfigurationError,
    OAuthError,
    OAuthFlowType,
    OAuthManager,
    OAuthProvider,
    OAuthState,
    OAuthToken,
    OAuthTokenError,
    authorize_google,
    get_oauth_manager,
)
from .store import (
    CredentialNotFoundError,
    CredentialSource,
    CredentialStore,
    CredentialStoreError,
    KeyringUnavailableError,
    StoredCredential,
    get_credential_store,
    get_credentials,
)


__all__: list[str] = [
    "CredentialLoader",
    "CredentialNotFoundError",
    "CredentialSource",
    "CredentialStore",
    "CredentialStoreError",
    "KeyringUnavailableError",
    "OAuthAuthorizationError",
    "OAuthCallbackError",
    "OAuthConfig",
    "OAuthConfigurationError",
    "OAuthError",
    "OAuthFlowType",
    "OAuthManager",
    "OAuthProvider",
    "OAuthState",
    "OAuthToken",
    "OAuthTokenError",
    "ProviderCredentialMapping",
    "StoredCredential",
    "authorize_google",
    "get_credential_loader",
    "get_credential_store",
    "get_credentials",
    "get_oauth_manager",
]
