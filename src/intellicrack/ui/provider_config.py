# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Provider configuration dialog for Intellicrack.

This module provides the UI for configuring LLM providers, including API key management, model selection, and connection settings.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final, Literal, cast

import httpx
from PyQt6.QtCore import Qt, QThread, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.config import get_config_file, get_env_file
from intellicrack.core.logging import get_logger
from intellicrack.core.types import AuthenticationError, ProviderCredentials, ProviderError, ProviderName
from intellicrack.credentials.env_loader import (
    create_env_template,
    get_api_key_env_var_mapping,
    get_credential_loader,
)
from intellicrack.credentials.oauth import (
    OAUTH_CONFIGS,
    OAuthConfig,
    OAuthConfigurationError,
    OAuthProvider,
    get_oauth_manager,
)
from intellicrack.credentials.store import CredentialStore, get_credential_store
from intellicrack.providers.display_names import NO_API_KEY_PROVIDER_IDS, provider_display_name
from intellicrack.providers.huggingface import fetch_router_served_model_ids
from intellicrack.ui.dialogs_helpers import show_error, show_info, show_warning
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine, run_bridge_coroutine_async
from intellicrack.ui.resources import IconManager
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)


try:
    from intellicrack.providers.local_transformers import LocalTransformersProvider
except ImportError:
    _logger.debug("local_transformers_unavailable")
    LocalTransformersProvider = None

try:
    from intellicrack.providers.ollama import OllamaProvider
except ImportError:
    _logger.debug("ollama_provider_unavailable")
    OllamaProvider = None

try:
    from intellicrack.providers.openrouter import OpenRouterProvider
except ImportError:
    _logger.debug("openrouter_provider_unavailable")
    OpenRouterProvider = None

try:
    from intellicrack.providers.grok import GrokProvider
except ImportError:
    _logger.debug("grok_provider_unavailable")
    GrokProvider = None

try:
    from intellicrack.providers.xpu_utils import (
        check_windows_requirements,
        clear_xpu_cache,
        get_optimal_dtype_for_xpu,
        get_xpu_device_count,
        get_xpu_device_info,
        get_xpu_memory_info,
        is_xpu_available,
    )
except ImportError:
    _logger.debug("xpu_utils_unavailable")
    check_windows_requirements = None
    clear_xpu_cache = None
    get_optimal_dtype_for_xpu = None
    get_xpu_device_count = None
    get_xpu_device_info = None
    get_xpu_memory_info = None
    is_xpu_available = None

try:
    from intellicrack.providers.model_loader import (
        RECOMMENDED_MODELS_B580,
        clear_global_cache,
        set_global_cache_size,
    )

    _recommended_local_models: list[dict[str, object]] = RECOMMENDED_MODELS_B580
except ImportError:
    _logger.debug("model_loader_unavailable")
    clear_global_cache = None
    set_global_cache_size = None
    _recommended_local_models = []

_DIALOG_WIDTH: Final[int] = 800
_DIALOG_HEIGHT: Final[int] = 550
_DISCOVERY_WIDTH: Final[int] = 500
_DISCOVERY_HEIGHT: Final[int] = 400
_LIST_MIN_WIDTH: Final[int] = 200
_LIST_MAX_WIDTH: Final[int] = 250
_KEY_INPUT_MIN_WIDTH: Final[int] = 280
_SHOW_KEY_MAX_WIDTH: Final[int] = 60
_MODEL_COMBO_MIN_WIDTH: Final[int] = 250
_LOOKUP_FAILED: Final[bool] = False


def _get_source_colors() -> dict[str, QColor]:
    """Get theme-aware colors for credential source indicators.

    Returns:
        dict[str, QColor]: Mapping of source names to QColor values.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return {
            "env_file": QColor(34, 139, 34),
            "environment": QColor(70, 130, 180),
            "manual": QColor(218, 165, 32),
            "not_configured": QColor(178, 34, 34),
            "default": QColor(128, 128, 128),
            "configured": QColor(34, 139, 34),
            "unconfigured": QColor(169, 169, 169),
        }
    return {
        "env_file": QColor(46, 125, 50),
        "environment": QColor(21, 101, 192),
        "manual": QColor(239, 108, 0),
        "not_configured": QColor(198, 40, 40),
        "default": QColor(117, 117, 117),
        "configured": QColor(46, 125, 50),
        "unconfigured": QColor(117, 117, 117),
    }


def _restyle(widget: QWidget) -> None:
    """Force a QSS re-evaluation after a dynamic property change.

    Args:
        widget: The widget whose style should be refreshed.
    """
    s = widget.style()
    if s is not None:
        s.unpolish(widget)
        s.polish(widget)


def _size_button_to_content(button: QPushButton) -> None:
    """Give a button a minimum width equal to its own size hint.

    Without this, a button packed two-per-row into a narrow column can be
    squeezed below the width its label needs, and Qt centre-clips the text
    instead of growing the column.

    Args:
        button: The push button to floor at its natural width.
    """
    button.setMinimumWidth(button.sizeHint().width())


def _row_content_width(row: QHBoxLayout) -> int:
    """Compute the width a row of buttons needs to show every label uncut.

    Args:
        row: The horizontal layout whose button items should be measured.

    Returns:
        int: The sum of each button's size-hint width plus the spacing
        between them and the row's own left/right content margins.
    """
    widths = [
        widget.sizeHint().width()
        for i in range(row.count())
        if (item := row.itemAt(i)) is not None and (widget := item.widget()) is not None
    ]
    if not widths:
        return 0
    margins = row.contentsMargins()
    spacing = row.spacing() * (len(widths) - 1)
    return sum(widths) + spacing + margins.left() + margins.right()


if TYPE_CHECKING:
    from intellicrack.core.types import ModelInfo
    from intellicrack.providers.base import LLMProviderBase
    from intellicrack.providers.discovery import DiscoveryEvent, ModelDiscovery
    from intellicrack.providers.openrouter import (
        OpenRouterProvider as _OpenRouterProviderType,
    )
    from intellicrack.providers.registry import ProviderRegistry

HTTP_OK = 200
_MAX_DISCOVERY_PREVIEW_ITEMS = 3

_PROVIDER_RESOURCE_LINKS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "anthropic": (
        ("Open Console", "https://console.anthropic.com/", "Open the Anthropic console to manage API keys and usage"),
        ("API Reference", "https://docs.anthropic.com/en/api/getting-started", "Open the Anthropic API documentation"),
        ("Pricing", "https://www.anthropic.com/pricing", "View current Anthropic model pricing"),
    ),
    "openai": (
        ("Open Platform", "https://platform.openai.com/", "Open the OpenAI platform dashboard"),
        ("API Reference", "https://platform.openai.com/docs/api-reference", "Open the OpenAI API documentation"),
        ("Usage Dashboard", "https://platform.openai.com/usage", "View OpenAI usage and billing"),
    ),
    "google": (
        ("Open AI Studio", "https://aistudio.google.com/", "Open Google AI Studio to manage API keys"),
        ("API Reference", "https://ai.google.dev/api", "Open the Gemini API documentation"),
        ("Pricing", "https://ai.google.dev/pricing", "View current Gemini model pricing"),
    ),
    "huggingface": (
        ("Open Hub", "https://huggingface.co/", "Open the Hugging Face Hub"),
        ("Token Settings", "https://huggingface.co/settings/tokens", "Manage Hugging Face access tokens"),
        ("Inference Endpoints", "https://ui.endpoints.huggingface.co/", "Manage Hugging Face inference endpoints"),
    ),
    "grok": (
        ("Open Console", "https://console.x.ai/", "Open the xAI console to manage API keys"),
        ("API Reference", "https://docs.x.ai/docs/api-reference", "Open the xAI API documentation"),
        ("Status Page", "https://status.x.ai/", "View xAI service status"),
    ),
    "openrouter": (
        ("Open Dashboard", "https://openrouter.ai/", "Open the OpenRouter dashboard"),
        ("API Reference", "https://openrouter.ai/docs", "Open the OpenRouter API documentation"),
        ("Activity", "https://openrouter.ai/activity", "View OpenRouter activity and usage"),
    ),
}

HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401


@dataclass(frozen=True)
class _RevokeOutcome:
    """Result of a "Revoke Token" credential-removal attempt.

    Attributes:
        kind: What kind of credential was targeted: ``"oauth"`` for an
            OAuth-capable provider's token, ``"api_key"`` for a stored API
            key deleted from the credential store, or ``"none"`` when the
            provider had no credential configured at all.
        success: Whether the revoke/delete actually removed a credential.
    """

    kind: Literal["oauth", "api_key", "none"]
    success: bool


async def _revoke_credential(
    provider_name: ProviderName,
    oauth_provider: OAuthProvider | None,
    *,
    store: CredentialStore | None = None,
) -> _RevokeOutcome:
    """Revoke the OAuth token for an OAuth-capable provider, else delete its API key.

    Providers that expose an OAuth flow (``oauth_provider is not None``)
    keep the existing behaviour of revoking through the OAuth manager.
    Every other provider -- anything :class:`~intellicrack.credentials.oauth.OAuthProvider`
    does not recognise, such as OpenAI, OpenRouter, Grok, Ollama, or local
    Transformers -- has its stored API key deleted from the credential
    store instead, so "Revoke Token" never silently no-ops for API-key
    providers.

    Args:
        provider_name: Canonical provider identifier used by the credential store.
        oauth_provider: The OAuth provider enum when the provider supports
            OAuth, or ``None`` for API-key-only providers.
        store: Credential store used for the API-key path. Defaults to the
            shared global store; overridable so callers (including tests)
            can target an isolated store instance.

    Returns:
        _RevokeOutcome: What kind of credential was targeted and whether the
        revoke/delete actually succeeded.
    """
    if oauth_provider is not None:
        manager = get_oauth_manager()
        success = await manager.revoke_token(oauth_provider)
        return _RevokeOutcome(kind="oauth", success=success)

    resolved_store = store or get_credential_store()
    source = await resolved_store.get_source(provider_name)
    if source is None:
        return _RevokeOutcome(kind="none", success=False)

    deleted = await resolved_store.delete(provider_name)
    return _RevokeOutcome(kind="api_key", success=deleted)


class CredentialSource:
    """Constants for credential source identification."""

    ENV_FILE = ".env file"
    ENVIRONMENT = "environment"
    MANUAL = "manual entry"
    NOT_CONFIGURED = "not configured"


class CredentialSourceDetector:
    """Detects where credentials were loaded from.

    Identifies whether API credentials came from a .env file, environment
    variables, manual configuration, or are not configured at all.

    Attributes:
        ENV_VAR_MAPPING: Mapping of provider names to their API key environment variable names.
    """

    ENV_VAR_MAPPING: ClassVar[dict[str, str]] = get_api_key_env_var_mapping()

    def __init__(self, config_path: Path) -> None:
        """Initialize the CredentialSourceDetector for a given config path.

        Args:
            config_path: Path to the provider configuration JSON file.
        """
        self._config_path = config_path
        self._env_file_vars: set[str] = set()
        self._load_env_file_vars()

    def _load_env_file_vars(self) -> None:
        """Load variable names present in .env file."""
        env_paths = [
            Path.cwd() / ".env",
            get_env_file(),
            Path.home() / ".env",
        ]

        for env_path in env_paths:
            _logger.debug("env_file_scanning", path=str(env_path))
            if not self._parse_env_file(env_path):
                continue
            _logger.info(
                "env_file_loaded",
                path=str(env_path),
                keys=len(self._env_file_vars),
            )
            break

    def _parse_env_file(self, env_path: Path) -> bool:
        """Extract variable names from a single ``.env`` file into ``_env_file_vars``.

        Args:
            env_path: Filesystem path to the candidate ``.env`` file.

        Returns:
            bool: ``True`` if the file was opened and parsed, ``False`` if the file
            could not be opened (in which case the caller should try the next path).
        """
        try:
            with env_path.open("r", encoding="utf-8") as f:
                for line in f:
                    self._collect_env_var_name(line)
        except OSError:
            _logger.warning("env_file_read_failed", path=str(env_path))
            return False
        return True

    def _collect_env_var_name(self, line: str) -> None:
        """Add the variable name from a single ``.env`` line to ``_env_file_vars``.

        Args:
            line: One raw line from the ``.env`` file (including leading/trailing whitespace).
        """
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            return
        key = stripped.split("=", 1)[0].strip()
        if key.startswith("export "):
            key = key[7:].strip()
        if key:
            self._env_file_vars.add(key)

    def detect_source(self, provider_id: str, current_key: str) -> str:
        """Detect the source of credentials for a provider.

        Args:
            provider_id: The provider identifier.
            current_key: The currently configured API key.

        Returns:
            str: Credential source string from CredentialSource constants.
        """
        if not current_key:
            return CredentialSource.NOT_CONFIGURED

        env_var = self.ENV_VAR_MAPPING.get(provider_id)
        if not env_var:
            return CredentialSource.MANUAL

        if env_var in self._env_file_vars:
            env_value = os.environ.get(env_var, "")
            if env_value == current_key:
                return CredentialSource.ENV_FILE

        if os.environ.get(env_var) == current_key:
            return CredentialSource.ENVIRONMENT

        if self._config_path.exists():
            _logger.debug(
                "provider_config_probing",
                config_path=str(self._config_path),
                provider=provider_id,
            )
            try:
                with self._config_path.open("r", encoding="utf-8") as f:
                    config = json.load(f)
                    if provider_id in config and config[provider_id].get("api_key") == current_key:
                        return CredentialSource.MANUAL
            except (OSError, json.JSONDecodeError):
                _logger.warning("config_file_read_failed", config_path=str(self._config_path))
        return CredentialSource.MANUAL

    @staticmethod
    def get_source_color(source: str) -> QColor:
        """Get the display color for a credential source.

        Args:
            source: The credential source string.

        Returns:
            QColor: QColor for the source indicator.
        """
        colors = _get_source_colors()
        source_key_map = {
            CredentialSource.ENV_FILE: "env_file",
            CredentialSource.ENVIRONMENT: "environment",
            CredentialSource.MANUAL: "manual",
            CredentialSource.NOT_CONFIGURED: "not_configured",
        }
        key = source_key_map.get(source, "default")
        return colors.get(key, colors["default"])


class ConnectionTestWorker(QThread):
    """Worker thread for testing provider connections.

    Runs connection tests in a separate thread to avoid blocking the UI.

    Attributes:
        test_finished: Signal emitted when test completes with (success, message).
    """

    test_finished: ClassVar[pyqtSignal] = pyqtSignal(bool, str)

    def __init__(
        self,
        provider_id: str,
        api_key: str,
        api_base: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ConnectionTestWorker for a provider.

        Args:
            provider_id: Identifier of the provider to test.
            api_key: API key to use for the connection test.
            api_base: Optional custom API base URL.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.provider_id = provider_id
        self._api_key = api_key
        self._api_base = api_base

    def run(self) -> None:
        """Run the connection test in a separate thread."""
        try:
            success, message = self._test_provider_connection()
            self.test_finished.emit(success, message)
        except (RuntimeError, OSError, ValueError) as e:
            _logger.warning("connection_test_failed", provider=self.provider_id, error=str(e))
            success = False
            self.test_finished.emit(success, f"Connection error: {e}")

    @staticmethod
    def _classify_probe_response(
        provider: str,
        status_code: int,
        success_message: str,
        *,
        invalid_key_status: int = HTTP_UNAUTHORIZED,
        invalid_key_message: str = "Invalid API key",
    ) -> tuple[bool, str]:
        """Map an HTTP probe status code to a (success, message) tuple and log the outcome.

        Args:
            provider: Provider identifier used in structured logs.
            status_code: HTTP status code returned by the probe call.
            success_message: User-facing message returned on HTTP 200.
            invalid_key_status: Status code interpreted as an invalid credential.
            invalid_key_message: User-facing message returned for an invalid credential.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        if status_code == HTTP_OK:
            _logger.info(
                "provider_http_probe_succeeded",
                provider=provider,
                status_code=status_code,
            )
            return True, success_message
        if status_code == invalid_key_status:
            _logger.warning(
                "provider_http_probe_unauthorized",
                provider=provider,
                status_code=status_code,
            )
            return False, invalid_key_message
        _logger.warning(
            "provider_http_probe_http_error",
            provider=provider,
            status_code=status_code,
        )
        return False, f"API error: {status_code}"

    def _test_provider_connection(self) -> tuple[bool, str]:
        """Test the connection to the provider.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        timeout = httpx.Timeout(10.0)

        _logger.info(
            "provider_connection_test_starting",
            provider=self.provider_id,
        )

        if self.provider_id == "anthropic":
            return self._test_anthropic(timeout)
        if self.provider_id == "openai":
            return self._test_openai(timeout)
        if self.provider_id == "google":
            return self._test_google(timeout)
        if self.provider_id == "ollama":
            return self._test_ollama(timeout)
        if self.provider_id == "openrouter":
            return self._test_openrouter(timeout)
        if self.provider_id == "huggingface":
            return self._test_huggingface(timeout)
        if self.provider_id == "grok":
            return self._test_grok(timeout)
        if self.provider_id == "local_transformers":
            return self._test_local_transformers()
        _logger.warning(
            "provider_connection_test_unknown_provider",
            provider=self.provider_id,
        )
        return False, f"Unknown provider: {self.provider_id}"

    @staticmethod
    def _test_local_transformers() -> tuple[bool, str]:
        """Verify the local Transformers inference backend is usable.

        Local inference exposes no network endpoint, so the connection
        test routes through a real ``LocalTransformersProvider`` instance:
        ``connect`` probes PyTorch availability and selects the compute
        backend (CUDA, Intel XPU, or CPU). The resolved device is reported
        back so the user sees exactly what inference will run on. No API
        key or credentials are involved.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        if LocalTransformersProvider is None:
            _logger.warning("local_transformers_provider_unavailable")
            return False, "Local Transformers provider is unavailable (install PyTorch and transformers)"

        provider = LocalTransformersProvider()

        async def _probe() -> tuple[bool, str]:
            """Connect the local provider and report the resolved compute device.

            Returns:
                tuple[bool, str]: Success flag and a human-readable readiness
                message naming the selected device, or a failure reason.
            """
            try:
                await provider.connect(ProviderCredentials())
            except ProviderError as exc:
                _logger.warning("provider_test_failed", provider="local_transformers", error=str(exc))
                return False, str(exc)
            try:
                device_labels = {"cuda": "CUDA GPU", "xpu": "Intel XPU", "cpu": "CPU"}
                label = device_labels.get(provider.device_type, provider.device_type)
                return True, f"Ready for local inference on {label}"
            finally:
                await provider.disconnect()

        try:
            result = run_bridge_coroutine(_probe())
        except (RuntimeError, OSError, ValueError) as exc:
            _logger.warning("provider_test_failed", provider="local_transformers", error=str(exc))
            return False, str(exc)
        if result is None:
            return False, "Local Transformers test scheduled on running loop"
        return result

    def _test_anthropic(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test Anthropic API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        base_url = (self._api_base or "https://api.anthropic.com").rstrip("/")
        url = f"{base_url}/v1/models?limit=1"
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
        }
        _logger.debug("provider_http_probe", provider="anthropic", method="GET", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
        except httpx.ConnectError:
            _logger.warning("provider_connect_failed", provider="anthropic")
            return False, "Could not connect to Anthropic API"
        except (httpx.HTTPError, OSError, ValueError) as e:
            _logger.warning("provider_test_failed", provider="anthropic", error=str(e))
            return False, str(e)
        return self._classify_probe_response(
            "anthropic",
            response.status_code,
            "Connected to Anthropic API",
        )

    def _test_openai(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test OpenAI API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        base_url = self._api_base or "https://api.openai.com/v1"
        url = f"{base_url}/models"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _logger.debug("provider_http_probe", provider="openai", method="GET", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
        except httpx.ConnectError:
            _logger.warning("provider_connect_failed", provider="openai")
            return False, "Could not connect to OpenAI API"
        except (httpx.HTTPError, OSError, ValueError) as e:
            _logger.warning("provider_test_failed", provider="openai", error=str(e))
            return False, str(e)
        return self._classify_probe_response(
            "openai",
            response.status_code,
            "Connected to OpenAI API",
        )

    def _test_google(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test Google Gemini API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        headers = {"x-goog-api-key": self._api_key}
        _logger.debug("provider_http_probe", provider="google", method="GET", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
        except httpx.ConnectError:
            _logger.warning("provider_connect_failed", provider="google")
            return False, "Could not connect to Google API"
        except (httpx.HTTPError, OSError, ValueError) as e:
            _logger.warning("provider_test_failed", provider="google", error=str(e))
            return False, str(e)
        return self._classify_probe_response(
            "google",
            response.status_code,
            "Connected to Google Gemini API",
            invalid_key_status=HTTP_BAD_REQUEST,
        )

    def _test_ollama(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test Ollama connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        base_url = self._api_base or "http://localhost:11434"
        url = f"{base_url}/api/tags"
        _logger.debug("provider_http_probe", provider="ollama", method="GET", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url)
        except httpx.ConnectError:
            _logger.warning("provider_connect_failed", provider="ollama")
            return False, "Could not connect to Ollama (is it running?)"
        except (httpx.HTTPError, OSError, ValueError) as e:
            _logger.warning("provider_test_failed", provider="ollama", error=str(e))
            return False, str(e)
        if response.status_code == HTTP_OK:
            _logger.info(
                "provider_http_probe_succeeded",
                provider="ollama",
                status_code=response.status_code,
            )
            return True, "Connected to Ollama"
        _logger.warning(
            "provider_http_probe_http_error",
            provider="ollama",
            status_code=response.status_code,
        )
        return False, f"Ollama error: {response.status_code}"

    def _test_openrouter(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test OpenRouter API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        base_url = self._api_base or "https://openrouter.ai/api/v1"
        url = f"{base_url}/models"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _logger.debug("provider_http_probe", provider="openrouter", method="GET", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
        except httpx.ConnectError:
            _logger.warning("provider_connect_failed", provider="openrouter")
            return False, "Could not connect to OpenRouter API"
        except (httpx.HTTPError, OSError, ValueError) as e:
            _logger.warning("provider_test_failed", provider="openrouter", error=str(e))
            return False, str(e)
        return self._classify_probe_response(
            "openrouter",
            response.status_code,
            "Connected to OpenRouter API",
        )

    def _test_huggingface(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test HuggingFace Inference API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        url = "https://huggingface.co/api/models"
        params = {"filter": "text-generation", "limit": 1}
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _logger.debug("provider_http_probe", provider="huggingface", method="GET", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, params=params, headers=headers)
        except httpx.ConnectError:
            _logger.warning("provider_connect_failed", provider="huggingface")
            return False, "Could not connect to HuggingFace API"
        except (httpx.HTTPError, OSError, ValueError) as e:
            _logger.warning("provider_test_failed", provider="huggingface", error=str(e))
            return False, str(e)
        return self._classify_probe_response(
            "huggingface",
            response.status_code,
            "Connected to HuggingFace API",
            invalid_key_message="Invalid API token",
        )

    def _test_grok(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test X.AI Grok API connection.

        Prefers routing through a live GrokProvider instance so provider-level
        validation (SDK auth handling, base URL handling) is exercised end-to-end.
        Falls back to a direct ``GET https://api.x.ai/v1/models`` call when the
        Grok provider module is unavailable.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, str]: Tuple of (success, message).
        """
        if not self._api_key:
            return False, "Grok API key required"

        if GrokProvider is not None:
            provider = GrokProvider()
            creds = ProviderCredentials(api_key=self._api_key, api_base=self._api_base)

            async def _probe() -> tuple[bool, str]:
                """Authenticate against Grok through the live provider instance.

                Returns:
                    tuple[bool, str]: Success flag and a short status message
                    describing the connection outcome.
                """
                try:
                    await provider.connect(creds)
                except AuthenticationError as exc:
                    _logger.warning("provider_test_failed", provider="grok", error=str(exc))
                    return False, "Invalid API key"
                except ProviderError as exc:
                    _logger.warning("provider_test_failed", provider="grok", error=str(exc))
                    return False, str(exc)
                try:
                    return True, "Connected to Grok API"
                finally:
                    await provider.disconnect()

            try:
                result = run_bridge_coroutine(_probe())
            except (RuntimeError, OSError, ValueError) as exc:
                _logger.warning("provider_test_failed", provider="grok", error=str(exc))
                return False, str(exc)
            if result is None:
                return False, "Grok test scheduled on running loop"
            return result

        base_url = (self._api_base or "https://api.x.ai/v1").rstrip("/")
        url = f"{base_url}/models"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _logger.debug("provider_http_probe", provider="grok", method="GET", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
        except httpx.ConnectError:
            _logger.warning("provider_connect_failed", provider="grok")
            return False, "Could not connect to Grok API"
        except (httpx.HTTPError, OSError, ValueError) as e:
            _logger.warning("provider_test_failed", provider="grok", error=str(e))
            return False, str(e)
        return self._classify_probe_response(
            "grok",
            response.status_code,
            "Connected to Grok API",
        )


class ModelRefreshWorker(QThread):
    """Worker thread for refreshing model lists from provider APIs.

    Attributes:
        refresh_finished: Signal emitted when refresh completes with (success, models, message).
    """

    refresh_finished: ClassVar[pyqtSignal] = pyqtSignal(bool, list, str)

    def __init__(
        self,
        provider_id: str,
        api_key: str,
        api_base: str | None = None,
        provider: LLMProviderBase | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ModelRefreshWorker for a provider.

        Args:
            provider_id: Identifier of the provider to refresh models for.
            api_key: API key to authenticate with the provider.
            api_base: Optional custom API base URL.
            provider: Optional pre-connected provider instance to use directly.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.provider_id = provider_id
        self._api_key = api_key
        self._api_base = api_base
        self._provider = provider

    def run(self) -> None:
        """Run the model refresh in a separate thread."""
        try:
            success, models, message = self._fetch_models()
            self.refresh_finished.emit(success, models, message)
        except (RuntimeError, OSError, ValueError) as e:
            _logger.warning("model_refresh_failed", error=str(e))
            success = False
            self.refresh_finished.emit(success, [], f"Error fetching models: {e}")

    def _fetch_models(self) -> tuple[bool, list[str], str]:
        """Fetch available models from the provider API.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        if self._provider is not None and self._provider.is_connected:
            try:
                model_infos = asyncio.run(self._provider.list_models())
                if model_ids := sorted(m.id for m in model_infos):
                    return True, model_ids, f"Found {len(model_ids)} models"
            except (RuntimeError, OSError, ValueError) as exc:
                _logger.warning(
                    "provider_list_models_fallback",
                    provider=self.provider_id,
                    error=str(exc),
                )

        timeout = httpx.Timeout(15.0)

        if self.provider_id == "anthropic":
            return self._fetch_anthropic_models(timeout)
        if self.provider_id == "openai":
            return self._fetch_openai_models(timeout)
        if self.provider_id == "google":
            return self._fetch_google_models(timeout)
        if self.provider_id == "ollama":
            return self._fetch_ollama_models(timeout)
        if self.provider_id == "openrouter":
            return self._fetch_openrouter_models(timeout)
        if self.provider_id == "huggingface":
            return self._fetch_huggingface_models(timeout)
        if self.provider_id == "grok":
            return self._fetch_grok_models(timeout)
        if self.provider_id == "local_transformers":
            return self._fetch_local_transformers_models()
        return False, [], f"Unknown provider: {self.provider_id}"

    @staticmethod
    def _fetch_local_transformers_models() -> tuple[bool, list[str], str]:
        """Return locally loadable Transformers model identifiers.

        Local inference needs no API call or credentials: the curated
        recommended-model catalogue is returned directly so the dropdown
        is populated even before any model is downloaded or the provider
        is connected. When a connected provider is present the caller has
        already preferred its richer ``list_models`` result; this method
        is the always-available fallback.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        if model_ids := sorted(
            {str(entry["model_id"]) for entry in _recommended_local_models if "model_id" in entry},
        ):
            return True, model_ids, f"Found {len(model_ids)} local models"
        return False, [], "No local Transformers models available"

    def _fetch_anthropic_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch Anthropic models from the /v1/models API with pagination.

        Args:
            timeout: HTTP request timeout configuration.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        if not self._api_key:
            return False, [], "No Anthropic API key configured"

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
        }
        base_url = (self._api_base or "https://api.anthropic.com").rstrip("/")
        url = f"{base_url}/v1/models"
        all_models: list[str] = []
        page_count = 0

        _logger.info("model_fetch_starting", provider="anthropic", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                outcome = self._collect_anthropic_pages(client, url, headers, all_models)
        except (httpx.HTTPError, OSError, ValueError, KeyError) as e:
            _logger.warning(
                "model_fetch_failed",
                provider="anthropic",
                error=str(e),
                pages_fetched=page_count,
            )
            return False, [], f"API unavailable: {e}"

        outcome_kind, message, page_count = outcome
        if outcome_kind == "unauthorized":
            return False, [], message
        if outcome_kind == "http_error":
            return False, [], message
        if not all_models:
            _logger.warning("model_fetch_empty", provider="anthropic", pages=page_count)
            return False, [], "No models returned"

        all_models.sort()
        _logger.info(
            "model_fetch_succeeded",
            provider="anthropic",
            model_count=len(all_models),
            pages=page_count,
        )
        return True, all_models, f"Found {len(all_models)} Anthropic models"

    @staticmethod
    def _collect_anthropic_pages(
        client: httpx.Client,
        url: str,
        headers: dict[str, str],
        all_models: list[str],
    ) -> tuple[str, str, int]:
        """Page through Anthropic's models endpoint, mutating ``all_models``.

        Args:
            client: Open httpx client used to issue paginated GET requests.
            url: Fully qualified models endpoint URL.
            headers: Request headers including auth and anthropic-version.
            all_models: Caller-owned list extended in place with discovered model ids.

        Returns:
            tuple[str, str, int]: Tuple of (outcome_kind, message, pages_fetched).
            ``outcome_kind`` is one of ``"ok"``, ``"unauthorized"``, ``"http_error"``.
        """
        after_id: str | None = None
        page_count = 0
        for _ in range(10):
            params: dict[str, str | int] = {"limit": 100}
            if after_id is not None:
                params["after_id"] = after_id

            page_count += 1
            _logger.debug(
                "model_fetch_page",
                provider="anthropic",
                page=page_count,
                after_id=after_id,
            )
            resp = client.get(url, headers=headers, params=params)
            if resp.status_code == HTTP_UNAUTHORIZED:
                _logger.warning(
                    "model_fetch_unauthorized",
                    provider="anthropic",
                    status_code=resp.status_code,
                )
                return "unauthorized", "Invalid API key", page_count
            if resp.status_code >= HTTP_BAD_REQUEST:
                _logger.warning(
                    "model_fetch_http_error",
                    provider="anthropic",
                    status_code=resp.status_code,
                )
                return "http_error", f"API error {resp.status_code}", page_count

            data = resp.json()
            all_models.extend(model_id for model_entry in data.get("data", []) if (model_id := model_entry.get("id", "")))

            if not data.get("has_more", False):
                break
            if last_id := data.get("last_id"):
                after_id = last_id
            else:
                break
        return "ok", "", page_count

    def _fetch_openai_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch OpenAI models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "https://api.openai.com/v1"
        url = f"{base_url}/models"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _logger.info("model_fetch_starting", provider="openai", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
                data = response.json() if response.status_code == HTTP_OK else None
        except (httpx.HTTPError, OSError, KeyError) as e:
            _logger.warning("model_fetch_failed", provider="openai", error=str(e))
            return False, [], str(e)

        if data is None:
            _logger.warning(
                "model_fetch_http_error",
                provider="openai",
                status_code=response.status_code,
            )
            return False, [], f"API error: {response.status_code}"

        non_chat_prefixes = (
            "text-embedding-",
            "dall-e-",
            "whisper-",
            "tts-",
            "text-moderation-",
            "davinci-",
            "babbage-",
            "canary-",
            "codex-",
            "text-davinci-",
            "text-babbage-",
            "text-curie-",
            "text-ada-",
            "code-davinci-",
            "code-cushman-",
        )
        models = [m["id"] for m in data.get("data", []) if not m["id"].startswith(non_chat_prefixes)]
        models.sort(reverse=True)
        _logger.info(
            "model_fetch_succeeded",
            provider="openai",
            model_count=len(models),
        )
        return True, models[:20], f"Found {len(models)} OpenAI models"

    def _fetch_google_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch Google Gemini models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        headers = {"x-goog-api-key": self._api_key}
        _logger.info("model_fetch_starting", provider="google", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
                data = response.json() if response.status_code == HTTP_OK else None
        except (httpx.HTTPError, OSError, KeyError) as e:
            _logger.warning("model_fetch_failed", provider="google", error=str(e))
            return False, [], str(e)

        if data is None:
            _logger.warning(
                "model_fetch_http_error",
                provider="google",
                status_code=response.status_code,
            )
            return False, [], f"API error: {response.status_code}"

        models = [
            m["name"].replace("models/", "")
            for m in data.get("models", [])
            if "gemini" in m["name"].lower() and "embedding" not in m["name"].lower()
        ]
        _logger.info(
            "model_fetch_succeeded",
            provider="google",
            model_count=len(models),
        )
        return True, models, f"Found {len(models)} Gemini models"

    def _fetch_ollama_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch installed Ollama models.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "http://localhost:11434"
        url = f"{base_url}/api/tags"
        _logger.info("model_fetch_starting", provider="ollama", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url)
                data = response.json() if response.status_code == HTTP_OK else None
        except (httpx.HTTPError, OSError, KeyError) as e:
            _logger.warning("model_fetch_failed", provider="ollama", error=str(e))
            return False, [], str(e)

        if data is None:
            _logger.warning(
                "model_fetch_http_error",
                provider="ollama",
                status_code=response.status_code,
            )
            return False, [], f"Ollama error: {response.status_code}"

        models = [m["name"] for m in data.get("models", [])]
        _logger.info(
            "model_fetch_succeeded",
            provider="ollama",
            model_count=len(models),
        )
        return True, models, f"Found {len(models)} Ollama models"

    def _fetch_openrouter_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch OpenRouter models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "https://openrouter.ai/api/v1"
        url = f"{base_url}/models"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _logger.info("model_fetch_starting", provider="openrouter", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
                data = response.json() if response.status_code == HTTP_OK else None
        except (httpx.HTTPError, OSError, KeyError) as e:
            _logger.warning("model_fetch_failed", provider="openrouter", error=str(e))
            return False, [], str(e)

        if data is None:
            _logger.warning(
                "model_fetch_http_error",
                provider="openrouter",
                status_code=response.status_code,
            )
            return False, [], f"API error: {response.status_code}"

        models = [m["id"] for m in data.get("data", [])]
        models.sort()
        _logger.info(
            "model_fetch_succeeded",
            provider="openrouter",
            model_count=len(models),
        )
        return True, models[:50], f"Found {len(models)} OpenRouter models"

    def _fetch_huggingface_models(
        self,
        timeout: httpx.Timeout,
    ) -> tuple[bool, list[str], str]:
        """Fetch HuggingFace text-generation models actually served by an Inference Provider.

        Fetches the Hub's text-generation catalog, then intersects it
        against the HuggingFace Inference Providers router's served-model
        set -- fetched through the shared
        :func:`~intellicrack.providers.huggingface.fetch_router_served_model_ids`
        helper -- so this disconnected-provider fallback honors the same
        served-models contract as
        :meth:`~intellicrack.providers.huggingface.HuggingFaceProvider.list_models`
        instead of listing every Hub-tagged model regardless of whether any
        configured Inference Provider currently serves it for chat
        completion. When the router request fails the refresh reports
        failure with an explanatory message rather than falling back to
        the unfiltered (and potentially unservable) Hub catalog.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        url = "https://huggingface.co/api/models"
        params = {
            "filter": "text-generation-inference",
            "sort": "downloads",
            "direction": -1,
            "limit": 50,
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _logger.info("model_fetch_starting", provider="huggingface", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, params=params, headers=headers)
                data = response.json() if response.status_code == HTTP_OK else None
        except (httpx.HTTPError, OSError, KeyError) as e:
            _logger.warning("model_fetch_failed", provider="huggingface", error=str(e))
            return False, [], str(e)

        if data is None:
            _logger.warning(
                "model_fetch_http_error",
                provider="huggingface",
                status_code=response.status_code,
            )
            return False, [], f"API error: {response.status_code}"

        catalog_ids = [m["id"] for m in data if m.get("pipeline_tag") in {"text-generation", "conversational"}]

        try:
            served_ids = asyncio.run(fetch_router_served_model_ids(self._api_key, timeout, self._api_base))
        except (httpx.HTTPError, OSError, ValueError) as e:
            _logger.warning("huggingface_served_models_fetch_failed", error=str(e))
            return False, [], f"Failed to fetch HuggingFace Inference Providers served-model catalog: {e}"

        models = [model_id for model_id in catalog_ids if model_id in served_ids]
        _logger.info(
            "model_fetch_succeeded",
            provider="huggingface",
            model_count=len(models),
        )
        return (
            True,
            models[:30],
            f"Found {len(models)} HuggingFace models",
        )

    def _fetch_grok_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch X.AI Grok models.

        Prefers routing through a live GrokProvider instance (connect + list_models)
        so the same code path the main application uses is exercised. Falls back to a
        direct ``GET https://api.x.ai/v1/models`` call when the Grok provider module
        is unavailable.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            tuple[bool, list[str], str]: Tuple of (success, model_list, message).
        """
        if not self._api_key:
            return False, [], "No Grok API key configured"

        if GrokProvider is not None:
            provider = GrokProvider()
            creds = ProviderCredentials(api_key=self._api_key, api_base=self._api_base)

            async def _list() -> tuple[bool, list[str], str]:
                """Connect to Grok and collect sorted model identifiers.

                Returns:
                    tuple[bool, list[str], str]: Success flag, sorted model
                    ids when the listing succeeds, and a status message.
                """
                try:
                    await provider.connect(creds)
                except AuthenticationError as exc:
                    _logger.warning("model_fetch_failed", provider="grok", error=str(exc))
                    return False, [], "Invalid API key"
                except ProviderError as exc:
                    _logger.warning("model_fetch_failed", provider="grok", error=str(exc))
                    return False, [], str(exc)
                try:
                    model_infos = await provider.list_models()
                except ProviderError as exc:
                    _logger.warning("model_fetch_failed", provider="grok", error=str(exc))
                    return False, [], str(exc)
                finally:
                    await provider.disconnect()
                model_ids = sorted(m.id for m in model_infos)
                if model_ids:
                    return True, model_ids, f"Found {len(model_ids)} Grok models"
                return False, [], "No models returned"

            try:
                result = run_bridge_coroutine(_list())
            except (RuntimeError, OSError, ValueError) as exc:
                _logger.warning("model_fetch_failed", provider="grok", error=str(exc))
                return False, [], str(exc)
            if result is None:
                return False, [], "Grok fetch scheduled on running loop"
            return result

        base_url = (self._api_base or "https://api.x.ai/v1").rstrip("/")
        url = f"{base_url}/models"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        _logger.info("model_fetch_starting", provider="grok", url=url)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url, headers=headers)
                data = response.json() if response.status_code == HTTP_OK else None
        except (httpx.HTTPError, OSError, KeyError, ValueError) as e:
            _logger.warning("model_fetch_failed", provider="grok", error=str(e))
            return False, [], str(e)

        if response.status_code == HTTP_UNAUTHORIZED:
            _logger.warning(
                "model_fetch_unauthorized",
                provider="grok",
                status_code=response.status_code,
            )
            return False, [], "Invalid API key"
        if data is None:
            _logger.warning(
                "model_fetch_http_error",
                provider="grok",
                status_code=response.status_code,
            )
            return False, [], f"API error: {response.status_code}"

        models = sorted(m["id"] for m in data.get("data", []) if m.get("id"))
        _logger.info(
            "model_fetch_succeeded",
            provider="grok",
            model_count=len(models),
        )
        return True, models, f"Found {len(models)} Grok models"


class ProviderConfigDialog(QDialog):
    """Dialog for configuring LLM providers.

    Allows users to:
    - Enter API keys for each provider
    - Select default models
    - Configure timeout and retry settings
    - Test provider connections
    - Set active provider for analysis
    - View connection status and model counts

    Attributes:
        provider_updated: Signal emitted when a provider config changes.
        active_provider_changed: Signal emitted when active provider changes.
    """

    provider_updated: ClassVar[pyqtSignal] = pyqtSignal(str)
    active_provider_changed: ClassVar[pyqtSignal] = pyqtSignal(str)

    def __init__(
        self,
        provider_registry: ProviderRegistry | None = None,
        model_discovery: ModelDiscovery | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ProviderConfigDialog.

        Args:
            provider_registry: Optional registry of available LLM providers.
            model_discovery: Optional model discovery service for fetching available models.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._registry = provider_registry
        self._discovery = model_discovery
        self._provider_widgets: dict[str, ProviderSettingsWidget] = {}
        self._provider_items: dict[str, QListWidgetItem] = {}
        self._current_provider: str | None = None
        self._config_path = get_config_file("providers.json")
        self._credential_detector = CredentialSourceDetector(self._config_path)

        self._setup_ui()
        self._load_providers()
        self._update_status_timer = QTimer(self)
        self._update_status_timer.timeout.connect(self._refresh_provider_status)
        self._update_status_timer.start(30000)

        self._load_credential_overview()

        self.setWindowTitle("Provider Settings")
        self.resize(_DIALOG_WIDTH, _DIALOG_HEIGHT)

    def _load_credential_overview(self) -> None:
        """Load credential overview from env_loader and credential store."""
        try:
            self._refresh_credential_overview()
        except (RuntimeError, OSError, ValueError) as exc:
            _logger.warning(
                "credential_overview_load_skipped",
                error=str(exc),
            )

    def _refresh_credential_overview(self) -> None:
        """Populate ``_credential_overview`` and log the credential store snapshot.

        The env/`.env`-backed overview is computed synchronously (in-memory,
        no I/O). The keyring/file-backed credential-store enumeration is
        dispatched on the persistent bridge event loop via
        ``run_bridge_coroutine_async`` so a slow keyring backend cannot
        freeze the GUI thread while the dialog is constructed or refreshed.
        """
        loader = get_credential_loader()
        configured = loader.list_configured_providers()
        missing = loader.list_missing_providers()
        self._credential_overview: dict[str, Any] = {
            "configured": configured,
            "missing": missing,
        }
        _logger.info(
            "credential_overview",
            configured_count=len(configured),
            missing_count=len(missing),
        )

        store = CredentialStore()

        async def _load_store_credentials() -> int:
            """Enumerate credential-store providers and log each source.

            Returns:
                int: Number of providers present in the credential store.
            """
            store_providers = await store.list_providers()
            for cred in store_providers:
                source = await store.get_source(cred.provider)
                _logger.debug(
                    "credential_source",
                    provider=cred.provider.value,
                    source=str(source),
                )
            return len(store_providers)

        def _on_store_loaded(result: object) -> None:
            """Record how many providers were found in the credential store.

            Args:
                result: Provider count returned by the store enumeration
                    coroutine, or a non-int value treated as zero.
            """
            store_count = result if isinstance(result, int) else 0
            _logger.info(
                "credential_store_loaded",
                store_provider_count=store_count,
            )

        def _on_store_load_error(exc: object) -> None:
            """Log a credential-store enumeration failure without blocking the UI.

            Args:
                exc: Exception or error payload from the store load worker.
            """
            _logger.warning("credential_store_load_failed", error=str(exc))

        run_bridge_coroutine_async(
            _load_store_credentials(),
            on_success=_on_store_loaded,
            on_error=_on_store_load_error,
            parent=self,
        )

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        main_layout = QVBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QWidget()
        left_panel.setMinimumWidth(_LIST_MIN_WIDTH)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self._provider_list = QListWidget()
        self._provider_list.setMinimumWidth(_LIST_MIN_WIDTH)
        self._provider_list.setMaximumWidth(_LIST_MAX_WIDTH)
        self._provider_list.currentRowChanged.connect(self._on_provider_selected)
        left_layout.addWidget(self._provider_list)

        self._active_label = QLabel()
        self._active_label.setWordWrap(True)
        self._active_label.setObjectName("info_panel")
        self._update_active_label()
        left_layout.addWidget(self._active_label)

        action_layout = QHBoxLayout()
        self._set_active_btn = QPushButton("Set Active")
        self._set_active_btn.setToolTip("Set the selected provider as active for analysis")
        self._set_active_btn.clicked.connect(self._on_set_active)
        action_layout.addWidget(self._set_active_btn)

        self._refresh_status_btn = QPushButton("Refresh")
        self._refresh_status_btn.setToolTip("Refresh connection status for all providers")
        self._refresh_status_btn.clicked.connect(self._refresh_provider_status)
        action_layout.addWidget(self._refresh_status_btn)

        left_layout.addLayout(action_layout)

        cred_layout = QHBoxLayout()
        self._refresh_creds_btn = QPushButton("Reload Keys")
        self._refresh_creds_btn.setToolTip("Reload credentials from .env files and credential store")
        self._refresh_creds_btn.clicked.connect(self.refresh_credentials)
        cred_layout.addWidget(self._refresh_creds_btn)

        self._migrate_creds_btn = QPushButton("Migrate")
        self._migrate_creds_btn.setToolTip("Migrate credentials from .env to secure store")
        self._migrate_creds_btn.clicked.connect(self.migrate_credentials)
        cred_layout.addWidget(self._migrate_creds_btn)
        left_layout.addLayout(cred_layout)

        advanced_layout = QHBoxLayout()
        self._create_env_btn = QPushButton("Write .env Template")
        self._create_env_btn.setToolTip(
            "Write a .env credential template. Non-destructive: an existing .env is backed up "
            "and only missing variables are appended, existing values are never overwritten.",
        )
        self._create_env_btn.clicked.connect(self.create_env_template)
        advanced_layout.addWidget(self._create_env_btn)

        self._discover_models_btn = QPushButton("Discover")
        self._discover_models_btn.setToolTip("Discover models for selected provider")
        self._discover_models_btn.clicked.connect(self._on_discover_selected_provider)
        advanced_layout.addWidget(self._discover_models_btn)
        left_layout.addLayout(advanced_layout)

        oauth_layout = QHBoxLayout()
        self._oauth_btn = QPushButton("OAuth Login")
        self._oauth_btn.setToolTip("Start OAuth flow for selected provider")
        self._oauth_btn.clicked.connect(self._on_start_oauth)
        oauth_layout.addWidget(self._oauth_btn)

        self._revoke_btn = QPushButton("Revoke Token")
        self._revoke_btn.setToolTip("Revoke OAuth token for selected provider")
        self._revoke_btn.clicked.connect(self._on_revoke_oauth)
        oauth_layout.addWidget(self._revoke_btn)
        left_layout.addLayout(oauth_layout)

        action_buttons = (
            self._set_active_btn,
            self._refresh_status_btn,
            self._refresh_creds_btn,
            self._migrate_creds_btn,
            self._create_env_btn,
            self._discover_models_btn,
            self._oauth_btn,
            self._revoke_btn,
        )
        for action_btn in action_buttons:
            _size_button_to_content(action_btn)

        action_rows = (action_layout, cred_layout, advanced_layout, oauth_layout)
        widest_row_width = max(_row_content_width(row) for row in action_rows)
        left_panel.setMinimumWidth(max(_LIST_MIN_WIDTH, widest_row_width))

        self._settings_stack = QStackedWidget()

        splitter.addWidget(left_panel)
        splitter.addWidget(self._settings_stack)
        splitter.setSizes([220, 580])
        splitter.setChildrenCollapsible(False)

        main_layout.addWidget(splitter, stretch=1)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Apply,
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)

        if apply_button := button_box.button(QDialogButtonBox.StandardButton.Apply):
            apply_button.clicked.connect(self._on_apply)

        main_layout.addWidget(button_box)

    def _load_providers(self) -> None:
        """Load provider configurations into the list with status indicators."""
        providers = [
            ("Anthropic", "anthropic"),
            ("OpenAI", "openai"),
            ("Google Gemini", "google"),
            ("Ollama", "ollama"),
            ("OpenRouter", "openrouter"),
            ("HuggingFace", "huggingface"),
            ("Grok", "grok"),
            ("Local Transformers", "local_transformers"),
        ]

        active_name = self._get_active_provider_name()

        for display_name, provider_id in providers:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, provider_id)

            is_active = provider_id == active_name
            is_connected = self._is_provider_connected(provider_id)
            model_count = self._get_model_count(provider_id)

            self._update_provider_item_display(item, display_name, is_active=is_active, is_connected=is_connected, model_count=model_count)

            self._provider_list.addItem(item)
            self._provider_items[provider_id] = item

            widget = ProviderSettingsWidget(
                provider_id,
                self._registry,
                self._config_path,
                self._credential_detector,
                self._discovery,
            )

            def _conn_tested_slot(s: int, m: str) -> None:
                """Adapt a settings-widget connection_tested signal.

                Args:
                    s: Success flag from the widget as an integer (nonzero
                        means the connection test succeeded).
                    m: Status message accompanying the connection test.
                """
                self._on_widget_connection_tested(success=bool(s), _message=m)

            widget.connection_tested.connect(_conn_tested_slot)
            self._settings_stack.addWidget(widget)
            self._provider_widgets[provider_id] = widget

        if self._provider_list.count() > 0:
            self._provider_list.setCurrentRow(0)

    @staticmethod
    def _update_provider_item_display(
        item: QListWidgetItem,
        display_name: str,
        *,
        is_active: bool,
        is_connected: bool,
        model_count: int,
    ) -> None:
        """Update the display text and styling for a provider list item.

        Args:
            item: The list widget item to update.
            display_name: Human-readable provider name.
            is_active: Whether this is the active provider.
            is_connected: Whether the provider is connected.
            model_count: Number of available models.
        """
        status_indicator = "●" if is_connected else "○"
        active_marker = " ★" if is_active else ""
        model_info = f" ({model_count})" if model_count > 0 else ""

        item.setText(f"{status_indicator} {display_name}{active_marker}{model_info}")

        font = item.font()
        font.setBold(is_active)
        item.setFont(font)

        colors = _get_source_colors()
        if is_connected:
            item.setForeground(colors["configured"])
        else:
            item.setForeground(colors["unconfigured"])

    def _get_active_provider_name(self) -> str | None:
        """Get the name of the currently active provider.

        Returns:
            str | None: Provider ID of the active provider or None.
        """
        if self._registry is None:
            return None
        try:
            active = self._registry.active_name
        except (RuntimeError, AttributeError, ValueError) as exc:
            _logger.warning("active_provider_lookup_failed", error=str(exc))
            return None
        else:
            return active.value if active is not None else None

    def _is_provider_connected(self, provider_id: str) -> bool:
        """Check if a provider is connected.

        Args:
            provider_id: The provider identifier.

        Returns:
            bool: True if the provider is connected.
        """
        if self._registry is None:
            return False
        try:
            provider_name = ProviderName(provider_id)
            provider = self._registry.get(provider_name)
            return provider is not None and getattr(provider, "is_connected", False)
        except (RuntimeError, AttributeError, ValueError) as exc:
            _logger.warning(
                "provider_connection_check_failed",
                provider_id=provider_id,
                error=str(exc),
            )
            return False

    def _get_model_count(self, provider_id: str) -> int:
        """Get the number of available models for a provider.

        Args:
            provider_id: The provider identifier.

        Returns:
            int: Number of available models.
        """
        if self._discovery is None:
            return 0
        try:
            provider_name = ProviderName(provider_id)
            counts = self._discovery.get_provider_model_count()
            return counts.get(provider_name, 0)
        except (RuntimeError, AttributeError, ValueError) as exc:
            _logger.warning(
                "model_count_lookup_failed",
                provider_id=provider_id,
                error=str(exc),
            )
            return 0

    def _update_active_label(self) -> None:
        """Update the active provider display label."""
        if active_name := self._get_active_provider_name():
            display = provider_display_name(active_name)
            self._active_label.setText(f"<b>Active:</b> {display}")
        else:
            self._active_label.setText("<b>Active:</b> None selected")

    def _apply_active_provider(self, registry: ProviderRegistry, current_provider: str) -> None:
        """Mark ``current_provider`` active in ``registry`` and update the UI.

        Args:
            registry: Provider registry that owns the active selection.
            current_provider: Name of the provider to activate.
        """
        provider_name = ProviderName(current_provider)
        registry.set_active(provider_name)
        self._update_active_label()
        self._refresh_provider_status()
        self.active_provider_changed.emit(current_provider)
        _logger.info(
            "active_provider_changed",
            provider=current_provider,
        )

    def _on_set_active(self) -> None:
        """Handle set active button click."""
        if self._current_provider is None:
            show_warning(self, "No Selection", "Please select a provider first.")
            return

        if self._registry is None:
            show_warning(self, "Registry Error", "Provider registry not available.")
            return

        try:
            self._apply_active_provider(self._registry, self._current_provider)
        except ValueError:
            _logger.warning("unknown_provider_name", provider=self._current_provider)
            show_error(self, "Error", f"Unknown provider: {self._current_provider}")
        except (RuntimeError, AttributeError) as e:
            _logger.warning("set_active_provider_failed", provider=self._current_provider, error=str(e))
            show_error(self, "Error", f"Failed to set active provider: {e}")

    def _refresh_provider_status(self) -> None:
        """Refresh the connection status for all providers."""
        active_name = self._get_active_provider_name()
        overview = getattr(self, "_credential_overview", {})
        configured_providers: list[str] = list(overview.get("configured", []))

        for provider_id, item in self._provider_items.items():
            is_active = provider_id == active_name
            is_connected = self._is_provider_connected(provider_id)
            model_count = self._get_model_count(provider_id)
            has_credential = provider_id in configured_providers

            display_name = provider_display_name(provider_id)

            self._update_provider_item_display(
                item,
                display_name,
                is_active=is_active,
                is_connected=is_connected or has_credential,
                model_count=model_count,
            )

    def _on_widget_connection_tested(self, *, success: bool, _message: str) -> None:
        """Handle connection test completion from a widget.

        Args:
            success: Whether the connection test succeeded.
            _message: Status message (unused, logged by widget).
        """
        if success:
            self._refresh_provider_status()

    def _on_provider_selected(self, index: int) -> None:
        """Handle provider selection change.

        Args:
            index: The selected provider index.
        """
        if index >= 0 and (item := self._provider_list.item(index)):
            provider_id = item.data(Qt.ItemDataRole.UserRole)
            self._current_provider = provider_id
            self._settings_stack.setCurrentIndex(index)

    def _on_accept(self) -> None:
        """Handle dialog acceptance."""
        self._save_all_settings()
        self.accept()

    def _on_apply(self) -> None:
        """Handle apply button click."""
        self._save_all_settings()

    def _save_all_settings(self) -> None:
        """Save settings for all providers."""
        for provider_id, widget in self._provider_widgets.items():
            widget.save_settings()
            self.provider_updated.emit(provider_id)

    def get_settings(self) -> dict[str, dict[str, Any]]:
        """Get all provider settings.

        Returns:
            dict[str, dict[str, Any]]: Dictionary mapping provider IDs to their settings.
        """
        settings: dict[str, dict[str, Any]] = {provider_id: widget.get_settings() for provider_id, widget in self._provider_widgets.items()}
        return settings

    def _on_discover_selected_provider(self) -> None:
        """Discover models for the currently selected provider."""
        if self._current_provider is not None:
            self.discover_single_provider(self._current_provider)

    def _on_start_oauth(self) -> None:
        """Start OAuth flow for the currently selected provider."""
        if self._current_provider is not None:
            self.start_oauth_flow(self._current_provider)

    def _on_revoke_oauth(self) -> None:
        """Revoke OAuth token for the currently selected provider."""
        if self._current_provider is not None:
            self.revoke_oauth_token(self._current_provider)

    @staticmethod
    def _reload_credentials_from_store() -> None:
        """Reload provider credentials from env files and the credential store."""
        loader = get_credential_loader()
        loader.reload()

        configured = loader.list_configured_providers()
        missing = loader.list_missing_providers()

        for name in configured:
            env_var = loader.get_env_var(name.value)
            if env_var is not None:
                _logger.debug("credential_refreshed", provider=name)
        _logger.info(
            "credentials_reloaded",
            configured=len(configured),
            missing=len(missing),
        )

    def refresh_credentials(self) -> None:
        """Reload credentials from env files and credential store."""
        _logger.info("credential_refresh_starting")
        try:
            self._reload_credentials_from_store()
        except (RuntimeError, OSError, ValueError) as exc:
            _logger.warning("credential_refresh_failed", error=str(exc))
        self._load_credential_overview()

    def create_env_template(self) -> None:
        """Write or merge a .env credential template, then report the outcome.

        Never truncates an existing `.env`: pre-existing content is backed up to a timestamped ``.env.<timestamp>.bak`` file and only
        template variables missing from the file are appended, so any real credential already saved there is preserved.
        """
        env_file = get_env_file()
        _logger.info("env_template_creation_starting", path=str(env_file))
        try:
            result = create_env_template(env_file)
        except OSError as exc:
            _logger.warning("env_template_creation_failed", error=str(exc))
            show_error(self, "Write .env Template", f"Failed to write .env template: {exc}")
            self._load_credential_overview()
            return

        _logger.info(
            "env_template_created",
            path=str(result.path),
            created=result.created,
            merged=result.merged,
            backup_path=str(result.backup_path) if result.backup_path else None,
            added_keys=list(result.added_keys),
        )
        if result.created:
            show_info(self, "Write .env Template", f"Created a new .env template at {result.path}.")
        elif result.added_keys:
            added = ", ".join(result.added_keys)
            show_info(
                self,
                "Write .env Template",
                f"Existing .env was preserved (backup: {result.backup_path}).\nAppended missing variables: {added}.",
            )
        else:
            show_info(
                self,
                "Write .env Template",
                f"Existing .env already defines every template variable; no changes were made (backup: {result.backup_path}).",
            )
        self._load_credential_overview()

    def migrate_credentials(self) -> None:
        """Migrate credentials from env files to credential store.

        The store write runs on the persistent bridge event loop via
        ``run_bridge_coroutine_async`` so the keyring/file I/O performed for
        every provider found in the environment cannot freeze the GUI
        thread; the credential overview is reloaded once migration
        completes, whether it succeeded or failed.
        """
        _logger.info("credential_migration_starting", source=".env")
        store = CredentialStore()

        def _on_success(_result: object) -> None:
            """Reload the credential overview after env migration succeeds.

            Args:
                _result: Migration coroutine return value; unused because
                    only completion triggers the overview refresh.
            """
            _logger.info("credentials_migrated_from_env", source=".env")
            self._load_credential_overview()

        def _on_error(exc: object) -> None:
            """Log migration failure and still refresh the credential overview.

            Args:
                exc: Exception or error payload from the migration worker.
            """
            _logger.warning("credential_migration_failed", error=str(exc))
            self._load_credential_overview()

        run_bridge_coroutine_async(
            store.migrate_from_env(),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
        )

    def discover_single_provider(self, provider_name: str) -> None:
        """Discover models for a specific provider.

        The network round-trip to the provider's model-listing API runs on
        the persistent bridge event loop via ``run_bridge_coroutine_async``
        so it cannot freeze the GUI thread; provider status is refreshed
        once discovery completes.

        Args:
            provider_name: Name of the provider to discover models for.
        """
        if self._discovery is None:
            return
        discovery = self._discovery
        try:
            pname = ProviderName(provider_name)
        except ValueError:
            _logger.warning("unknown_provider_for_discovery", provider=provider_name)
            return

        async def _discover() -> None:
            """Run model discovery for the selected provider on the bridge loop."""
            await discovery.discover_provider(pname)

        def _on_success(_result: object) -> None:
            """Refresh provider status after discovery events are recorded.

            Args:
                _result: Discovery coroutine return value; unused because
                    status is refreshed from the discovery event buffer.
            """
            events = discovery.get_discovery_events()
            _logger.debug(
                "provider_discovery_events",
                provider=provider_name,
                event_count=len(events),
            )
            self._refresh_provider_status()

        def _on_error(exc: object) -> None:
            """Log a single-provider discovery failure on the GUI thread.

            Args:
                exc: Exception or error payload from the discovery worker.
            """
            _logger.warning(
                "provider_discovery_failed",
                provider=provider_name,
                error=str(exc),
            )

        run_bridge_coroutine_async(_discover(), on_success=_on_success, on_error=_on_error, parent=self)

    def start_oauth_flow(self, provider_id: str) -> None:
        """Start an OAuth authorization flow for a provider.

        Args:
            provider_id: The provider to authorize.
        """
        try:
            oauth_provider = OAuthProvider(provider_id)
        except ValueError:
            _logger.warning("oauth_unknown_provider", provider=provider_id)
            return

        oauth_config = OAUTH_CONFIGS.get(oauth_provider)
        if oauth_config is None:
            _logger.warning("oauth_no_config", provider=provider_id)
            return

        _logger.info("oauth_flow_starting", provider=provider_id)
        self._run_oauth_flow(provider_id, oauth_provider, oauth_config)

    def _run_oauth_flow(
        self,
        provider_id: str,
        oauth_provider: OAuthProvider,
        oauth_config: OAuthConfig,
    ) -> None:
        """Execute the OAuth authorization flow and persist obtained credentials.

        The flow opens the user's browser and waits for the OAuth callback,
        a human-timescale wait. It is dispatched on the persistent bridge
        event loop via ``run_bridge_coroutine_async`` so the wait cannot
        freeze the GUI thread; the credential overview is reloaded once the
        flow completes, whether it succeeded or failed.

        Args:
            provider_id: The provider identifier used for logging and widget lookup.
            oauth_provider: Enum value identifying the OAuth provider.
            oauth_config: Provider-specific OAuth configuration.
        """
        manager = get_oauth_manager()

        async def _run_oauth() -> ProviderCredentials | None:
            """Complete the browser OAuth flow and materialize provider credentials.

            Returns:
                ProviderCredentials | None: Credentials derived from the OAuth
                tokens, or ``None`` when conversion yields no usable secret.
            """
            await manager.run_authorization_flow(oauth_config)
            return await manager.to_provider_credentials(oauth_provider)

        def _on_success(result: object) -> None:
            """Apply obtained OAuth credentials to the provider settings widget.

            Args:
                result: Credentials object from the OAuth worker, or another
                    payload treated as a missing credential set.
            """
            creds = result if isinstance(result, ProviderCredentials) else None
            if creds is not None and creds.api_key:
                _logger.info("oauth_credentials_obtained", provider=provider_id)
                widget = self._provider_widgets.get(provider_id)
                if widget is not None:
                    widget.set_api_key(creds.api_key)
            else:
                _logger.warning("oauth_credentials_missing", provider=provider_id)
            self._load_credential_overview()

        def _on_error(exc: object) -> None:
            """Surface OAuth flow failures to the user and refresh the credential overview.

            A missing ``client_id`` surfaces as :class:`OAuthConfigurationError`
            from :meth:`~intellicrack.credentials.oauth.OAuthManager.build_authorization_url`;
            that specific case gets an actionable message telling the user which
            environment variable to set. Every other OAuth failure still gets a
            generic error dialog so the button never fails silently.

            Args:
                exc: Exception or error payload from the OAuth worker.
            """
            _logger.warning("oauth_flow_failed", provider=provider_id, error=str(exc))
            display = provider_display_name(provider_id)
            if isinstance(exc, OAuthConfigurationError):
                show_error(
                    self,
                    "OAuth Login",
                    f"No OAuth client_id is configured for {display}. Set the "
                    f"{oauth_provider.value.upper()}_OAUTH_CLIENT_ID environment variable before "
                    "starting OAuth login for this provider.",
                )
            else:
                show_error(self, "OAuth Login", f"OAuth login failed for {display}: {exc}")
            self._load_credential_overview()

        run_bridge_coroutine_async(_run_oauth(), on_success=_on_success, on_error=_on_error, parent=self)

    def _do_revoke_oauth_token(self, provider_id: str) -> None:
        """Revoke the OAuth token for an OAuth-capable provider, else delete its API key.

        Providers that resolve to a valid :class:`OAuthProvider` keep the
        existing behaviour of revoking through the OAuth manager. Every
        other configured provider -- one :class:`OAuthProvider` does not
        recognise, such as OpenAI, OpenRouter, Grok, Ollama, or local
        Transformers -- has its stored API key deleted from the credential
        store instead, so the button never silently no-ops for API-key
        providers. When nothing is configured for the provider at all, the
        ``on_success`` handler reports that explicitly rather than staying
        silent.

        The revoke/delete work is dispatched on the persistent bridge event
        loop via ``run_bridge_coroutine_async`` so it cannot freeze the GUI
        thread; the credential overview is reloaded once it completes,
        whether it succeeded or failed.

        Args:
            provider_id: The provider whose credential should be revoked.
        """
        try:
            provider_name = ProviderName(provider_id)
        except ValueError:
            _logger.warning("unknown_provider_for_revoke", provider=provider_id)
            show_error(self, "Revoke Credential", f"Unknown provider: {provider_id}")
            return

        try:
            oauth_provider: OAuthProvider | None = OAuthProvider(provider_id)
        except ValueError:
            oauth_provider = None

        def _on_success(result: object) -> None:
            """Surface the revoke/delete outcome and refresh the credential overview.

            Args:
                result: The :class:`_RevokeOutcome` produced by
                    ``_revoke_credential``, or another payload treated as
                    "nothing was revoked".
            """
            outcome = result if isinstance(result, _RevokeOutcome) else _RevokeOutcome(kind="none", success=False)
            display = provider_display_name(provider_id)
            if outcome.kind == "oauth":
                _logger.info("oauth_token_revoked", provider=provider_id, success=outcome.success)
            elif outcome.kind == "api_key" and outcome.success:
                _logger.info("api_key_revoked", provider=provider_id)
                show_info(self, "Revoke Credential", f"Stored API key removed for {display}.")
            elif outcome.kind == "api_key":
                _logger.warning("api_key_revoke_failed", provider=provider_id)
                show_warning(
                    self,
                    "Revoke Credential",
                    f"No stored API key could be removed for {display} from the secure credential store. It may be "
                    "defined only via a .env file or environment variable, which must be edited directly.",
                )
            else:
                _logger.info("revoke_nothing_configured", provider=provider_id)
                show_warning(self, "Revoke Credential", f"No credential is configured for {display}; nothing to revoke.")
            self._load_credential_overview()

        def _on_error(exc: object) -> None:
            """Surface a revoke/delete failure and still refresh the overview.

            Args:
                exc: Exception or error payload from the revoke worker.
            """
            _logger.warning("revoke_credential_failed", provider=provider_id, error=str(exc))
            show_error(self, "Revoke Credential", f"Failed to revoke the credential for {provider_display_name(provider_id)}: {exc}")
            self._load_credential_overview()

        run_bridge_coroutine_async(
            _revoke_credential(provider_name, oauth_provider),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
        )

    def revoke_oauth_token(self, provider_id: str) -> None:
        """Revoke the OAuth token or delete the stored API key for a provider.

        Args:
            provider_id: The provider whose credential should be revoked.
        """
        _logger.info("revoke_credential_starting", provider=provider_id)
        self._do_revoke_oauth_token(provider_id)


class ProviderSettingsWidget(QFrame):
    """Widget for configuring a single provider.

    Displays API key input, model selection, connection settings,
    and credential source information for a specific LLM provider.

    Attributes:
        connection_tested: Signal emitted after connection test.
        ollama_pull_progress: Signal emitted per ``pull_model`` status chunk
            with ``(model_name, status)``.
        ollama_pull_finished: Signal emitted on ``pull_model`` completion with
            ``(success, model_name, message)``.
        generation_lookup_finished: Signal emitted on OpenRouter generation
            cost lookup completion with ``(success, generation_id, message)``.
    """

    connection_tested: ClassVar[pyqtSignal] = pyqtSignal(bool, str)
    ollama_pull_progress: ClassVar[pyqtSignal] = pyqtSignal(str, str)
    ollama_pull_finished: ClassVar[pyqtSignal] = pyqtSignal(bool, str, str)
    generation_lookup_finished: ClassVar[pyqtSignal] = pyqtSignal(bool, str, str)

    def __init__(
        self,
        provider_id: str,
        registry: ProviderRegistry | None = None,
        config_path: Path | None = None,
        credential_detector: CredentialSourceDetector | None = None,
        model_discovery: ModelDiscovery | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ProviderSettingsWidget for a single provider.

        Args:
            provider_id: Identifier of the provider to configure.
            registry: Optional provider registry for connection management.
            config_path: Optional path to the provider configuration file.
            credential_detector: Optional detector for identifying credential sources.
            model_discovery: Optional model discovery service.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.provider_id = provider_id
        self._registry = registry
        self._config_path = config_path or get_config_file("providers.json")
        self._credential_detector = credential_detector
        self._discovery = model_discovery
        self._models: list[ModelInfo] = []
        self._test_worker: ConnectionTestWorker | None = None
        self._refresh_worker: ModelRefreshWorker | None = None
        self._pending_saved_model: str = ""

        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel(f"<h3>{self._get_display_name()} Settings</h3>")
        layout.addWidget(title)

        credentials_group = QGroupBox("Credentials")
        credentials_layout = QFormLayout()

        api_key_row = QHBoxLayout()
        self._api_key_input = QLineEdit()
        self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_input.setMinimumWidth(_KEY_INPUT_MIN_WIDTH)
        self._api_key_input.textChanged.connect(self._on_api_key_changed)
        api_key_row.addWidget(self._api_key_input)

        self._show_key_btn = QPushButton("Show")
        self._show_key_btn.setMaximumWidth(_SHOW_KEY_MAX_WIDTH)
        self._show_key_btn.setCheckable(True)

        def _key_visibility_slot(checked: int) -> None:
            """Map the Show-key button toggle to plain-text vs masked key display.

            Args:
                checked: Qt ``toggled`` payload; nonzero reveals the API key.
            """
            self._toggle_key_visibility(show=bool(checked))

        self._show_key_btn.toggled.connect(_key_visibility_slot)
        api_key_row.addWidget(self._show_key_btn)

        credentials_layout.addRow("API Key:", api_key_row)

        self._credential_source_label = QLabel()
        self._credential_source_label.setObjectName("credential_source_label")
        credentials_layout.addRow("Source:", self._credential_source_label)

        self._api_base_input: QLineEdit | None
        self._org_id_input: QLineEdit | None

        if self.provider_id == "ollama":
            self._api_base_input = QLineEdit()
            self._api_base_input.setText("http://localhost:11434")
            credentials_layout.addRow("API Base URL:", self._api_base_input)
        elif self.provider_id in {"openai", "openrouter"}:
            self._api_base_input = QLineEdit()
            credentials_layout.addRow("API Base URL (optional):", self._api_base_input)
        else:
            self._api_base_input = None

        if self.provider_id == "openai":
            self._org_id_input = QLineEdit()
            credentials_layout.addRow("Organization ID:", self._org_id_input)
        else:
            self._org_id_input = None

        credentials_group.setLayout(credentials_layout)
        layout.addWidget(credentials_group)

        if self.provider_id == "local_transformers":
            credentials_group.setVisible(False)
            no_credentials_note = QLabel(
                "Local Transformers runs models directly on this machine (CPU/Intel XPU/CUDA). No API key or credentials are required.",
            )
            no_credentials_note.setWordWrap(True)
            no_credentials_note.setObjectName("hint_label")
            layout.addWidget(no_credentials_note)

        model_group = QGroupBox("Model Settings")
        model_layout = QFormLayout()

        model_row = QHBoxLayout()
        self._model_combo = QComboBox()
        self._model_combo.setMinimumWidth(_MODEL_COMBO_MIN_WIDTH)
        model_row.addWidget(self._model_combo)

        self._refresh_models_btn = QPushButton("Refresh")
        self._refresh_models_btn.clicked.connect(self._refresh_models)
        model_row.addWidget(self._refresh_models_btn)
        model_row.addStretch()

        model_layout.addRow("Default Model:", model_row)

        self._recommended_label = QLabel()
        self._recommended_label.setWordWrap(True)
        self._recommended_label.setObjectName("hint_label")
        model_layout.addRow("", self._recommended_label)

        model_group.setLayout(model_layout)
        layout.addWidget(model_group)

        connection_group = QGroupBox("Connection Settings")
        connection_layout = QFormLayout()

        self._enabled_checkbox = QCheckBox("Enable this provider")
        self._enabled_checkbox.setChecked(True)
        connection_layout.addRow(self._enabled_checkbox)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(10, 600)
        self._timeout_spin.setValue(120)
        self._timeout_spin.setSuffix(" seconds")
        connection_layout.addRow("Timeout:", self._timeout_spin)

        self._retries_spin = QSpinBox()
        self._retries_spin.setRange(0, 10)
        self._retries_spin.setValue(3)
        connection_layout.addRow("Max Retries:", self._retries_spin)

        connection_group.setLayout(connection_layout)
        layout.addWidget(connection_group)

        test_layout = QHBoxLayout()
        self._test_btn = QPushButton("Test Connection")
        self._test_btn.clicked.connect(self._test_connection)
        test_layout.addWidget(self._test_btn)

        self._status_icon = QLabel()
        self._status_icon.setFixedSize(20, 20)
        test_layout.addWidget(self._status_icon)

        self._status_label = QLabel()
        self._status_label.setObjectName("status_label")
        test_layout.addWidget(self._status_label)
        test_layout.addStretch()

        layout.addLayout(test_layout)

        self._setup_provider_specific_ui(layout)

        layout.addStretch()

    def _setup_provider_specific_ui(self, layout: QVBoxLayout) -> None:
        """Add provider-specific UI elements.

        Each supported provider receives a dedicated UI section so the configuration
        dialog exposes provider-specific capabilities consistently. Cloud providers
        receive a "Resources" group with deep links to their console, API reference,
        and other operational pages so users can manage credentials and usage without
        leaving the application. Providers with additional capabilities (model
        downloads for Ollama, device tuning for local transformers, generation cost
        lookup for OpenRouter) receive their bespoke groups in addition to or in
        place of the generic resources block.

        Args:
            layout: Parent layout to add widgets to.
        """
        if self.provider_id == "ollama":
            self._add_ollama_pull_group(layout)
            return
        if self.provider_id == "local_transformers":
            self._setup_xpu_settings(layout)
            return
        if self.provider_id == "openrouter":
            self._add_openrouter_cost_group(layout)
        self._add_provider_resource_links(layout)

    def _add_ollama_pull_group(self, layout: QVBoxLayout) -> None:
        """Add the Ollama model download group to the layout.

        Args:
            layout: Parent layout to add the group to.
        """
        pull_group = QGroupBox("Model Download")
        pull_form = QFormLayout()
        self._pull_model_input = QLineEdit()
        self._pull_model_input.setToolTip("Enter model name, e.g. llama3.3:latest")
        pull_btn = QPushButton("Pull Model")
        pull_btn.setToolTip("Download an Ollama model")
        pull_btn.clicked.connect(self._on_pull_model)
        pull_row = QHBoxLayout()
        pull_row.addWidget(self._pull_model_input)
        pull_row.addWidget(pull_btn)
        pull_form.addRow("Model:", pull_row)
        pull_group.setLayout(pull_form)
        layout.addWidget(pull_group)

    def _add_openrouter_cost_group(self, layout: QVBoxLayout) -> None:
        """Add the OpenRouter cost-lookup group to the layout.

        Args:
            layout: Parent layout to add the group to.
        """
        gen_group = QGroupBox("Cost Tracking")
        gen_form = QFormLayout()
        self._generation_id_input = QLineEdit()
        self._generation_id_input.setToolTip("Enter generation ID for cost lookup")
        gen_btn = QPushButton("Lookup Cost")
        gen_btn.setToolTip("Look up generation cost by ID")
        gen_btn.clicked.connect(self._on_lookup_generation)
        gen_row = QHBoxLayout()
        gen_row.addWidget(self._generation_id_input)
        gen_row.addWidget(gen_btn)
        gen_form.addRow("Generation ID:", gen_row)
        gen_group.setLayout(gen_form)
        layout.addWidget(gen_group)

    def _add_provider_resource_links(self, layout: QVBoxLayout) -> None:
        """Add a Resources group with deep links for the current provider.

        Builds one ``QPushButton`` per entry in ``_PROVIDER_RESOURCE_LINKS`` for the
        active provider. Each button opens the associated URL via
        ``QDesktopServices.openUrl`` so the system default browser is used and the
        action works on Windows, macOS, and Linux without spawning a subprocess.
        Buttons are stored on ``self._resource_buttons`` keyed by label so they can
        be exercised in tests without traversing the layout tree.

        Args:
            layout: Parent layout to add the group to.
        """
        links = _PROVIDER_RESOURCE_LINKS.get(self.provider_id)
        if not links:
            return

        resource_group = QGroupBox("Resources")
        resource_layout = QHBoxLayout()
        self._resource_buttons: dict[str, QPushButton] = {}

        for label, url, tooltip in links:
            btn = QPushButton(label)
            btn.setToolTip(tooltip)
            btn.clicked.connect(partial(self._open_resource_url, QUrl(url), label))
            resource_layout.addWidget(btn)
            self._resource_buttons[label] = btn

        resource_layout.addStretch()
        resource_group.setLayout(resource_layout)
        layout.addWidget(resource_group)

    def _open_resource_url(self, url: QUrl, label: str) -> None:
        """Open a provider resource URL in the system default browser.

        Args:
            url: The URL to open.
            label: Human-readable label for the link, used for logging.
        """
        if QDesktopServices.openUrl(url):
            _logger.info(
                "provider_resource_opened",
                provider=self.provider_id,
                label=label,
                url=url.toString(),
            )
        else:
            _logger.warning(
                "provider_resource_open_failed",
                provider=self.provider_id,
                label=label,
                url=url.toString(),
            )
            show_warning(
                self,
                "Open Link Failed",
                f"Could not open {label} ({url.toString()}).",
            )

    def _on_pull_model(self) -> None:
        """Handle pull model button click for Ollama."""
        model_input = getattr(self, "_pull_model_input", None)
        if model_input is None:
            return
        if model_name := model_input.text().strip():
            self.pull_ollama_model(model_name)

    def _set_status(self, message: str) -> None:
        """Update the provider status label text.

        Args:
            message: Human-readable status string to display.
        """
        status_label: QLabel | None = getattr(self, "_status_label", None)
        if status_label is not None:
            status_label.setText(message)

    def _on_ollama_pull_progress(self, model_name: str, status: str) -> None:
        """Forward Ollama pull progress to the status label.

        Args:
            model_name: The model being pulled.
            status: Current progress status message.
        """
        self._set_status(f"Pulling {model_name}: {status}")

    def _on_ollama_pull_finished(self, success: object, model_name: str, message: str) -> None:
        """Finalize UI state when an Ollama pull completes.

        Args:
            success: Whether the pull succeeded (received as Qt ``object`` slot arg).
            model_name: The model that was pulled.
            message: Outcome message.
        """
        ok: bool = bool(success)
        icon_manager = IconManager.get_instance()
        if ok:
            _logger.info("ollama_model_pulled", model=model_name)
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._set_status(message or f"Pulled {model_name}")
            show_info(self, "Ollama Pull", message or f"Pulled {model_name}")
            QTimer.singleShot(500, self._auto_refresh_models)
        else:
            _logger.warning("ollama_pull_failed", model=model_name, error=message)
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._set_status(message or f"Failed to pull {model_name}")
            show_warning(self, "Ollama Pull Failed", message or f"Failed to pull {model_name}")

    def _setup_xpu_settings(self, layout: QVBoxLayout) -> None:
        """Build the XPU / Device Settings group box for Local Transformers.

        When XPU is unavailable on the host, the periodic memory-refresh timer
        is stopped after the first sample and the group box is hidden so idle
        systems do not run a hot polling loop forever. When available, memory
        is refreshed at a 15s cadence.

        Args:
            layout: Parent layout to add the group box to.
        """
        xpu_group = QGroupBox("XPU / Device Settings")
        self._xpu_group = xpu_group
        form = QFormLayout()

        self._prefer_xpu_cb = QCheckBox("Prefer XPU over CPU")
        self._prefer_xpu_cb.setChecked(True)
        form.addRow(self._prefer_xpu_cb)

        self._device_combo = QComboBox()
        self._populate_device_combo()
        form.addRow("Device:", self._device_combo)

        dtype_row = QHBoxLayout()
        self._dtype_combo = QComboBox()
        self._dtype_combo.addItems(["Auto", "float16", "bfloat16", "float32"])
        dtype_row.addWidget(self._dtype_combo)
        auto_dtype_btn = QPushButton("Auto-Detect")
        auto_dtype_btn.setToolTip("Auto-detect optimal dtype for XPU inference")
        auto_dtype_btn.clicked.connect(self._on_detect_xpu_dtype)
        dtype_row.addWidget(auto_dtype_btn)
        form.addRow("Dtype:", dtype_row)

        self._xpu_mem_bar = QProgressBar()
        self._xpu_mem_bar.setRange(0, 100)
        self._xpu_mem_bar.setValue(0)
        self._xpu_mem_text = QLabel("--")
        mem_col = QVBoxLayout()
        mem_col.addWidget(self._xpu_mem_bar)
        mem_col.addWidget(self._xpu_mem_text)
        form.addRow("Memory:", mem_col)

        cache_row = QHBoxLayout()
        self._cache_spin = QSpinBox()
        self._cache_spin.setRange(512, 65536)
        self._cache_spin.setSingleStep(512)
        self._cache_spin.setValue(10240)
        self._cache_spin.setSuffix(" MB")
        cache_row.addWidget(self._cache_spin)
        apply_cache_btn = QPushButton("Apply")
        apply_cache_btn.clicked.connect(self._on_apply_cache_size)
        cache_row.addWidget(apply_cache_btn)
        form.addRow("Cache Limit:", cache_row)

        btn_row = QHBoxLayout()
        device_info_btn = QPushButton("Device Info")
        device_info_btn.clicked.connect(self._on_show_device_info)
        btn_row.addWidget(device_info_btn)
        clear_cache_btn = QPushButton("Clear Cache")
        clear_cache_btn.clicked.connect(self._on_clear_cache)
        btn_row.addWidget(clear_cache_btn)
        check_req_btn = QPushButton("Check Requirements")
        check_req_btn.clicked.connect(self._on_check_requirements)
        btn_row.addWidget(check_req_btn)
        form.addRow(btn_row)

        self._xpu_warnings_label = QLabel("")
        self._xpu_warnings_label.setWordWrap(True)
        form.addRow(self._xpu_warnings_label)

        xpu_group.setLayout(form)
        layout.addWidget(xpu_group)

        self._xpu_mem_timer = QTimer(self)
        self._xpu_mem_timer.timeout.connect(self._refresh_xpu_memory)
        self._refresh_xpu_memory()

        if self._is_xpu_available():
            self._xpu_mem_timer.start(15000)
        else:
            self._xpu_mem_timer.stop()
            xpu_group.hide()
            _logger.info("xpu_unavailable_ui_hidden", provider=self.provider_id)

    @staticmethod
    def _is_xpu_available() -> bool:
        """Probe whether an Intel XPU device is usable on this host.

        Returns:
            bool: True when ``is_xpu_available`` reports a usable device,
            False when the utility is missing or raises during the probe.
        """
        if is_xpu_available is None:
            return False
        try:
            return bool(is_xpu_available())
        except (RuntimeError, OSError):
            _logger.debug("xpu_availability_probe_failed", exc_info=True)
            return False

    def _populate_device_combo(self) -> None:
        """Populate the device selection combo with available XPU devices."""
        combo = self._device_combo
        combo.clear()

        if get_xpu_device_count is None or get_xpu_device_info is None:
            combo.addItem("CPU (XPU utils unavailable)", 0)
            return

        try:
            count = get_xpu_device_count()
        except (RuntimeError, OSError):
            _logger.debug("xpu_device_count_failed", exc_info=True)
            count = 0

        if count == 0:
            combo.addItem("CPU (no XPU devices)", 0)
            return

        for idx in range(count):
            try:
                info = get_xpu_device_info(idx)
            except (RuntimeError, OSError):
                _logger.debug("xpu_device_info_failed", device_index=idx, exc_info=True)
                combo.addItem(f"XPU:{idx} - Unknown", idx)
                continue

            if info is not None:
                mem_gb = info.total_memory_bytes / (1024.0 * 1024.0 * 1024.0)
                combo.addItem(f"XPU:{idx} - {info.device_name} ({mem_gb:.1f} GB)", idx)
            else:
                combo.addItem(f"XPU:{idx}", idx)

    def _read_xpu_memory_usage(self) -> tuple[int, int] | None:
        """Resolve the current XPU device and read its memory usage.

        Returns:
            tuple[int, int] | None: Tuple of ``(allocated_bytes, total_bytes)``
            when a device is available, or ``None`` when no XPU device is
            available or the required helpers are not importable.
        """
        if is_xpu_available is None or get_xpu_memory_info is None:
            return None
        if not is_xpu_available():
            return None

        device_idx: int = 0
        device_combo: QComboBox | None = getattr(self, "_device_combo", None)
        if device_combo is not None:
            data = device_combo.currentData()
            if isinstance(data, int):
                device_idx = data

        return get_xpu_memory_info(device_idx)

    def _refresh_xpu_memory(self) -> None:
        """Refresh the XPU memory usage bar and text label."""
        mem_bar: QProgressBar | None = getattr(self, "_xpu_mem_bar", None)
        mem_text: QLabel | None = getattr(self, "_xpu_mem_text", None)
        if mem_bar is None or mem_text is None:
            return

        if get_xpu_memory_info is None or is_xpu_available is None:
            mem_bar.setValue(0)
            mem_text.setText("XPU memory info not available")
            return

        try:
            usage = self._read_xpu_memory_usage()
        except (RuntimeError, OSError):
            _logger.debug("xpu_memory_refresh_failed", exc_info=True)
            mem_bar.setValue(0)
            mem_text.setText("Failed to read memory")
            return

        if usage is None:
            mem_bar.setValue(0)
            mem_text.setText("No XPU device")
            return

        allocated, total = usage

        if total > 0:
            pct = int((allocated / total) * 100)
            mem_bar.setValue(pct)
            alloc_gb = allocated / (1024.0 * 1024.0 * 1024.0)
            total_gb = total / (1024.0 * 1024.0 * 1024.0)
            mem_text.setText(f"{alloc_gb:.2f} GB / {total_gb:.2f} GB ({pct}%)")
        else:
            mem_bar.setValue(0)
            mem_text.setText("Unable to determine memory size")

    def _on_apply_cache_size(self) -> None:
        """Apply the configured cache size limit."""
        cache_spin: QSpinBox | None = getattr(self, "_cache_spin", None)
        if cache_spin is None or set_global_cache_size is None:
            return
        mb = cache_spin.value()
        set_global_cache_size(mb * 1024 * 1024)
        _logger.info("cache_size_applied", size_mb=mb)
        show_info(self, "Cache", f"Cache limit set to {mb} MB")

    def _on_clear_cache(self) -> None:
        """Clear the global model cache and XPU memory cache."""
        if clear_global_cache is not None:
            clear_global_cache()
        if clear_xpu_cache is not None:
            clear_xpu_cache()
        self._refresh_xpu_memory()
        _logger.info("caches_cleared")
        show_info(self, "Cache", "Model cache and XPU cache cleared")

    def _on_check_requirements(self) -> None:
        """Run Windows requirements check and display results."""
        warnings_label: QLabel | None = getattr(self, "_xpu_warnings_label", None)
        if warnings_label is None:
            return

        if check_windows_requirements is None:
            warnings_label.setText("Requirements check not available")
            warnings_label.setProperty("status", "idle")
            _restyle(warnings_label)
            return

        try:
            all_met, warnings = check_windows_requirements()
        except (RuntimeError, OSError):
            _logger.debug("requirements_check_failed", exc_info=True)
            warnings_label.setText("Failed to check requirements")
            warnings_label.setProperty("status", "error")
            _restyle(warnings_label)
            return

        if all_met and not warnings:
            warnings_label.setText("All system requirements met")
            warnings_label.setProperty("status", "success")
            _restyle(warnings_label)
        else:
            warnings_label.setText("\n".join(warnings))
            warnings_label.setProperty("status", "warning")
            _restyle(warnings_label)

    def _on_show_device_info(self) -> None:
        """Handle show device info button click."""
        info = self.get_provider_device_info()
        if info is not None:
            _logger.info("device_info_displayed", keys=list(info.keys()))
            show_info(self, "Device Info", "\n".join(f"{k}: {v}" for k, v in info.items()))

    def _on_detect_xpu_dtype(self) -> None:
        """Handle XPU dtype detection button click."""
        dtype = self.get_xpu_optimal_dtype()
        cached = getattr(self, "_xpu_dtype", None)
        display_dtype = cached if cached is not None else dtype
        if display_dtype is not None:
            dtype_combo: QComboBox | None = getattr(self, "_dtype_combo", None)
            if dtype_combo is not None:
                idx = dtype_combo.findText(display_dtype)
                if idx >= 0:
                    dtype_combo.setCurrentIndex(idx)
            show_info(self, "XPU Dtype", f"Optimal dtype: {display_dtype}")

    def _on_lookup_generation(self) -> None:
        """Handle generation cost lookup button click."""
        gen_input = getattr(self, "_generation_id_input", None)
        if gen_input is None:
            return
        gen_id = gen_input.text().strip()
        if not gen_id:
            return
        try:
            self.generation_lookup_finished.disconnect(self._on_generation_lookup_finished)
        except (TypeError, RuntimeError):
            _logger.debug("generation_lookup_finished_slot_not_connected", provider=self.provider_id)
        self.generation_lookup_finished.connect(self._on_generation_lookup_finished)
        self.get_openrouter_generation(gen_id)

    def _on_generation_lookup_finished(self, success: object, generation_id: str, message: str) -> None:
        """Display the outcome of an OpenRouter generation cost lookup.

        Args:
            success: Whether generation data was found (received as Qt ``object`` slot arg).
            generation_id: The generation ID that was looked up.
            message: Formatted cost lines on success, or a failure reason.
        """
        if bool(success):
            _logger.info("generation_lookup", id=generation_id)
            show_info(
                self,
                "Generation Cost",
                f"Generation: {generation_id}\n\n{message}",
            )
        else:
            show_warning(
                self,
                "Lookup Failed",
                message or f"No data found for generation ID: {generation_id}",
            )

    def _get_display_name(self) -> str:
        """Get the display name for the provider.

        Returns:
            str: Human-readable provider name.
        """
        return provider_display_name(self.provider_id)

    def _toggle_key_visibility(self, *, show: bool) -> None:
        """Toggle API key visibility.

        Args:
            show: Whether to show the key in plain text.
        """
        if show:
            self._api_key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._show_key_btn.setText("Hide")
        else:
            self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._show_key_btn.setText("Show")

    def _on_api_key_changed(self, text: str) -> None:
        """Handle API key text changes.

        Args:
            text: The current API key text.
        """
        self._update_credential_source_display(text)

    def _update_credential_source_display(self, api_key: str) -> None:
        """Update the credential source label based on current key.

        Args:
            api_key: The current API key value.
        """
        if self._credential_detector is None:
            self._credential_source_label.setText(CredentialSource.NOT_CONFIGURED)
            return

        source = self._credential_detector.detect_source(self.provider_id, api_key)
        color = self._credential_detector.get_source_color(source)

        self._credential_source_label.setText(source)
        self._credential_source_label.setStyleSheet(
            f"QLabel {{ padding: 4px 8px; border-radius: 3px; font-size: 11px; "
            f"background-color: rgba({color.red()}, {color.green()}, {color.blue()}, 0.2); "
            f"color: rgb({color.red()}, {color.green()}, {color.blue()}); }}",
        )

    def _compute_recommended_model_text(self, discovery: ModelDiscovery) -> str:
        """Determine the recommended-model label text for the provider.

        Args:
            discovery: Model discovery service used to resolve a recommendation.

        Returns:
            str: Label text for the recommended model, or an empty string when
            discovery cannot run (for example, inside a running event loop).
        """
        loop: asyncio.AbstractEventLoop | None = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            _logger.warning("no_running_event_loop", provider=self.provider_id)

        if loop is not None and loop.is_running():
            return ""

        if recommended := asyncio.run(
            discovery.get_recommended_model(self.provider_id),
        ):
            return f"Recommended: {recommended.name}"
        return ""

    def _update_recommended_model(self) -> None:
        """Update the recommended model label based on discovery."""
        if self._discovery is None:
            self._recommended_label.setText("")
            return

        try:
            self._recommended_label.setText(self._compute_recommended_model_text(self._discovery))
        except (RuntimeError, OSError, ValueError):
            _logger.exception("recommended_model_update_failed", provider=self.provider_id)
            self._recommended_label.setText("")

    def _load_settings(self) -> None:
        """Load settings from config file and environment."""
        saved_settings = self._load_from_config()
        _logger.info(
            "provider_settings_loaded",
            provider=self.provider_id,
        )

        env_vars = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "huggingface": "HUGGINGFACE_API_TOKEN",
            "local_transformers": "LOCAL_TRANSFORMERS_HF_TOKEN",
        }

        api_key = ""
        if self.provider_id in env_vars:
            env_key = os.environ.get(env_vars[self.provider_id], "")
            if not env_key and self.provider_id == "local_transformers":
                env_key = os.environ.get("HUGGINGFACE_API_TOKEN", "")
            config_key = saved_settings.get("api_key", "")
            api_key = config_key or env_key
            if api_key:
                self._api_key_input.setText(api_key)

        if self.provider_id == "ollama":
            base_url = saved_settings.get("api_base", os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
            if self._api_base_input:
                self._api_base_input.setText(base_url)
        elif self._api_base_input:
            base_url = saved_settings.get("api_base", "")
            self._api_base_input.setText(base_url)

        if self._org_id_input:
            org_id = saved_settings.get("organization_id", "")
            self._org_id_input.setText(org_id)

        self._enabled_checkbox.setChecked(saved_settings.get("enabled", True))
        self._timeout_spin.setValue(saved_settings.get("timeout_seconds", 120))
        self._retries_spin.setValue(saved_settings.get("max_retries", 3))

        if self.provider_id == "local_transformers":
            self._load_xpu_settings(saved_settings)

        saved_model: str = saved_settings.get("default_model", "")
        self._pending_saved_model = saved_model
        self._populate_default_models()

        self._update_credential_source_display(api_key)
        self._update_recommended_model()

        has_key = bool(self._api_key_input.text().strip())
        if has_key or self.provider_id in NO_API_KEY_PROVIDER_IDS:
            QTimer.singleShot(200, self._auto_refresh_models)

    def _load_from_config(self) -> dict[str, Any]:
        """Load settings from the config file.

        Returns:
            dict[str, Any]: Dictionary of saved settings for this provider.
        """
        if not self._config_path.exists():
            return {}

        try:
            with self._config_path.open(encoding="utf-8") as f:
                all_settings: dict[str, Any] = json.load(f)
                result: dict[str, Any] = all_settings.get(self.provider_id, {})
                return result
        except (json.JSONDecodeError, OSError) as e:
            _logger.warning("provider_config_load_failed", error=str(e))
            return {}

    def _load_xpu_settings(self, saved_settings: dict[str, Any]) -> None:
        """Restore XPU-specific settings from saved configuration.

        Args:
            saved_settings: Dictionary of saved settings for this provider.
        """
        prefer_cb: QCheckBox | None = getattr(self, "_prefer_xpu_cb", None)
        if prefer_cb is not None:
            prefer_cb.setChecked(saved_settings.get("prefer_xpu", True))

        dev_combo: QComboBox | None = getattr(self, "_device_combo", None)
        if dev_combo is not None:
            saved_idx = saved_settings.get("device_index", 0)
            if isinstance(saved_idx, int):
                combo_idx = dev_combo.findData(saved_idx)
                if combo_idx >= 0:
                    dev_combo.setCurrentIndex(combo_idx)

        dt_combo: QComboBox | None = getattr(self, "_dtype_combo", None)
        if dt_combo is not None:
            saved_dtype = saved_settings.get("dtype_override", "Auto")
            if isinstance(saved_dtype, str):
                dt_idx = dt_combo.findText(saved_dtype)
                if dt_idx >= 0:
                    dt_combo.setCurrentIndex(dt_idx)

        cache_sp: QSpinBox | None = getattr(self, "_cache_spin", None)
        if cache_sp is not None:
            saved_cache = saved_settings.get("cache_size_mb", 10240)
            if isinstance(saved_cache, int):
                cache_sp.setValue(saved_cache)

    def _populate_default_models(self) -> None:
        """Populate model dropdown with initial status text before API fetch."""
        self._model_combo.clear()
        has_key = bool(self._api_key_input.text().strip())
        if has_key or self.provider_id in NO_API_KEY_PROVIDER_IDS:
            self._model_combo.addItem("Loading models...")
        else:
            display = self._get_display_name()
            self._model_combo.addItem(f"No {display} API key configured")

    def _refresh_models(self) -> None:
        """Refresh the model list from the provider API."""
        _logger.debug("model_refresh_started", provider=self.provider_id)
        if self._refresh_worker is not None and self._refresh_worker.isRunning():
            _logger.debug("model_refresh_skipped", provider=self.provider_id, reason="refresh_in_progress")
            return
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_loading", 16))
        self._status_label.setText("Refreshing models...")
        self._refresh_models_btn.setEnabled(False)

        api_key = self._api_key_input.text().strip()
        api_base = self._api_base_input.text().strip() if self._api_base_input else None

        if not api_key and self.provider_id not in NO_API_KEY_PROVIDER_IDS:
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_warning", 16))
            self._status_label.setText("API key required to refresh models")
            self._refresh_models_btn.setEnabled(True)
            return

        provider = None
        if self._registry is not None:
            try:
                provider_name = ProviderName(self.provider_id)
                provider = self._registry.get(provider_name)
            except ValueError:
                _logger.warning("provider_name_parse_failed", provider_id=self.provider_id)

        self._refresh_worker = ModelRefreshWorker(
            self.provider_id,
            api_key,
            api_base,
            provider=provider,
            parent=self,
        )

        def _refresh_finished_slot(s: int, m: list[str], msg: str) -> None:
            """Adapt the model-refresh worker signal into the typed handler.

            Args:
                s: Success flag from the worker as an integer (nonzero means
                    the refresh succeeded).
                m: Model identifiers returned for this provider.
                msg: Status or error message produced by the refresh worker.
            """
            self._on_models_refreshed(success=bool(s), models=m, message=msg)

        self._refresh_worker.refresh_finished.connect(_refresh_finished_slot)
        self._refresh_worker.start()

    def _auto_refresh_models(self) -> None:
        """Auto-refresh models if no refresh is already running."""
        if self._refresh_worker is not None and self._refresh_worker.isRunning():
            _logger.debug("model_auto_refresh_skipped", provider=self.provider_id, reason="refresh_in_progress")
            return
        _logger.debug("model_auto_refresh_triggered", provider=self.provider_id)
        self._refresh_models()

    def _on_models_refreshed(self, *, success: bool, models: list[str], message: str) -> None:
        """Handle model refresh completion.

        Args:
            success: Whether refresh was successful.
            models: List of model IDs.
            message: Status message.
        """
        self._refresh_models_btn.setEnabled(True)
        icon_manager = IconManager.get_instance()

        if success and models:
            _logger.info(
                "provider_models_refreshed",
                provider=self.provider_id,
                model_count=len(models),
            )
            restore_model = self._pending_saved_model or self._model_combo.currentText()
            self._pending_saved_model = ""
            self._model_combo.clear()
            self._model_combo.addItems(models)
            idx = self._model_combo.findText(restore_model)
            if idx >= 0:
                self._model_combo.setCurrentIndex(idx)
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._status_label.setText(message)
        else:
            _logger.warning(
                "provider_models_refresh_failed",
                provider=self.provider_id,
                error=message or "Failed to refresh models",
            )
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText(message or "Failed to refresh models")

    def _test_connection(self) -> None:
        """Test the provider connection."""
        _logger.info(
            "provider_connection_test_started",
            provider=self.provider_id,
        )

        if self._test_worker is not None and self._test_worker.isRunning():
            _logger.debug("provider_connection_test_skipped", provider=self.provider_id, reason="test_in_progress")
            return

        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_loading", 16))
        self._status_label.setText("Testing connection...")
        self._test_btn.setEnabled(False)

        api_key = self._api_key_input.text().strip()
        api_base = self._api_base_input.text().strip() if self._api_base_input else None

        if not api_key and self.provider_id not in NO_API_KEY_PROVIDER_IDS:
            _logger.warning(
                "provider_connection_test_failed",
                provider=self.provider_id,
                error="API key required",
            )
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText("API key required")
            self._test_btn.setEnabled(True)
            return

        self._test_worker = ConnectionTestWorker(self.provider_id, api_key, api_base, self)

        def _test_finished_slot(s: int, m: str) -> None:
            """Adapt the connection-test worker signal into the typed handler.

            Args:
                s: Success flag from the worker as an integer (nonzero means
                    the connection test succeeded).
                m: Status message describing the connection test outcome.
            """
            self._on_connection_tested(success=bool(s), message=m)

        self._test_worker.test_finished.connect(_test_finished_slot)
        self._test_worker.start()

    def _on_connection_tested(self, *, success: bool, message: str) -> None:
        """Handle connection test completion.

        Args:
            success: Whether connection was successful.
            message: Status message.
        """
        self._test_btn.setEnabled(True)
        icon_manager = IconManager.get_instance()

        if success:
            _logger.info(
                "provider_connection_test_succeeded",
                provider=self.provider_id,
                status_message=message,
            )
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._status_label.setText(message)
            _logger.info(
                "auto_refresh_models_scheduled",
                provider=self.provider_id,
                delay_ms=500,
            )
            QTimer.singleShot(500, self._auto_refresh_models)
        else:
            _logger.warning(
                "provider_connection_test_failed",
                provider=self.provider_id,
                error=message,
            )
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText(message)

        self.connection_tested.emit(success, message)

    def set_api_key(self, api_key: str) -> None:
        """Set the API key input text.

        Args:
            api_key: The API key value to set.
        """
        self._api_key_input.setText(api_key)

    def _get_selected_model(self) -> str:
        """Return the selected model, or empty string if only status text is shown.

        Returns:
            str: Model ID string, or empty string if no real model is selected.
        """
        text = self._model_combo.currentText()
        return "" if text.startswith(("Loading models", "No ")) else text

    def get_settings(self) -> dict[str, Any]:
        """Get current settings as a dictionary.

        Returns:
            dict[str, Any]: Dictionary of current settings.
        """
        settings: dict[str, Any] = {
            "enabled": self._enabled_checkbox.isChecked(),
            "api_key": self._api_key_input.text().strip(),
            "default_model": self._get_selected_model(),
            "timeout_seconds": self._timeout_spin.value(),
            "max_retries": self._retries_spin.value(),
        }

        if self._api_base_input:
            settings["api_base"] = self._api_base_input.text().strip()

        if self._org_id_input:
            settings["organization_id"] = self._org_id_input.text().strip()

        if self.provider_id == "local_transformers":
            prefer_cb: QCheckBox | None = getattr(self, "_prefer_xpu_cb", None)
            if prefer_cb is not None:
                settings["prefer_xpu"] = prefer_cb.isChecked()

            dev_combo: QComboBox | None = getattr(self, "_device_combo", None)
            if dev_combo is not None:
                data = dev_combo.currentData()
                settings["device_index"] = data if isinstance(data, int) else 0

            dt_combo: QComboBox | None = getattr(self, "_dtype_combo", None)
            if dt_combo is not None:
                settings["dtype_override"] = dt_combo.currentText()

            cache_sp: QSpinBox | None = getattr(self, "_cache_spin", None)
            if cache_sp is not None:
                settings["cache_size_mb"] = cache_sp.value()

        return settings

    def save_settings(self) -> None:
        """Save current settings to config file and .env file."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)

        _logger.info(
            "provider_settings_save_starting",
            provider=self.provider_id,
            config_path=str(self._config_path),
        )

        all_settings: dict[str, dict[str, Any]] = {}
        if self._config_path.exists():
            try:
                with self._config_path.open(encoding="utf-8") as f:
                    all_settings = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                _logger.warning("provider_config_read_failed_using_empty", error=str(e))
                all_settings = {}

        settings = self.get_settings()
        has_api_key = bool(settings.pop("api_key", None))
        if has_api_key:
            all_settings[self.provider_id] = settings
        elif self.provider_id in all_settings:
            del all_settings[self.provider_id]

        try:
            with self._config_path.open("w", encoding="utf-8") as f:
                json.dump(all_settings, f, indent=2)
            _logger.info(
                "provider_settings_saved",
                provider=self.provider_id,
            )
        except OSError as e:
            _logger.exception(
                "provider_settings_save_failed",
                provider=self.provider_id,
            )
            show_warning(
                self,
                "Save Error",
                f"Failed to save settings: {e}",
            )

        self._persist_api_key_to_env()

    def _persist_api_key_to_env(self) -> None:
        """Persist the API key to the .env file."""
        api_key = self._api_key_input.text().strip()
        if not api_key:
            return

        env_var_mapping = get_api_key_env_var_mapping()

        if self.provider_id not in env_var_mapping:
            return

        env_var_name = env_var_mapping[self.provider_id]
        _logger.info(
            "env_credential_write_starting",
            provider=self.provider_id,
            env_var=env_var_name,
        )
        try:
            self._write_env_credentials(env_var_name, api_key)
        except OSError as e:
            _logger.warning(
                "env_file_update_failed",
                provider=self.provider_id,
                env_var=env_var_name,
                error=str(e),
            )
            show_warning(
                self,
                "Save Warning",
                f"Settings saved but failed to update .env file: {e}",
            )

    def _write_env_credentials(self, env_var_name: str, api_key: str) -> None:
        """Write the provider's API key (and Ollama host override) to the ``.env`` file.

        Args:
            env_var_name: Environment variable name that maps to ``provider_id``.
            api_key: Credential value to persist.
        """
        loader = get_credential_loader()
        loader.save_to_env_file(env_var_name, api_key)
        _logger.info(
            "env_credential_written",
            provider=self.provider_id,
            env_var=env_var_name,
        )

        if self.provider_id != "ollama" or not self._api_base_input:
            return
        host = self._api_base_input.text().strip()
        if not host or host == "http://localhost:11434":
            return
        loader.save_to_env_file("OLLAMA_HOST", host)
        _logger.info(
            "env_credential_written",
            provider=self.provider_id,
            env_var="OLLAMA_HOST",
        )

    def get_provider_device_info(self) -> dict[str, Any] | None:
        """Get device info for local transformer providers.

        Attempts to use the registered provider instance from the registry
        before falling back to creating a new provider.

        Returns:
            dict[str, Any] | None: Device information dict or None if not applicable.
        """
        if self.provider_id != "local_transformers":
            return None

        if self._registry is not None:
            registered = self._registry.get(ProviderName.LOCAL_TRANSFORMERS)
            if registered is not None:
                try:
                    get_info = getattr(registered, "get_device_info", None)
                    if callable(get_info):
                        result: object = get_info()
                        if isinstance(result, dict):
                            return cast("dict[str, Any]", result)
                except (RuntimeError, AttributeError):
                    _logger.debug("registry_device_info_failed", exc_info=True)

        if LocalTransformersProvider is None:
            return None
        try:
            provider = LocalTransformersProvider()
            return provider.get_device_info()
        except (RuntimeError, ImportError, AttributeError):
            _logger.debug("device_info_fetch_failed", exc_info=True)
            return None

    def pull_ollama_model(self, model_name: str) -> None:
        """Pull an Ollama model, streaming progress to the status label.

        Executes ``OllamaProvider.pull_model`` — an async generator yielding
        server-sent status lines — on the persistent bridge event loop via
        ``run_bridge_coroutine_async``. Each status chunk is forwarded to the
        Qt main thread through the ``ollama_pull_progress`` signal, and the
        terminal outcome via ``ollama_pull_finished``.

        Args:
            model_name: Name of the model to pull.
        """
        if self.provider_id != "ollama" or OllamaProvider is None:
            return

        try:
            self.ollama_pull_progress.disconnect(self._on_ollama_pull_progress)
        except (TypeError, RuntimeError):
            _logger.debug("ollama_pull_progress_slot_not_connected", provider=self.provider_id)
        try:
            self.ollama_pull_finished.disconnect(self._on_ollama_pull_finished)
        except (TypeError, RuntimeError):
            _logger.debug("ollama_pull_finished_slot_not_connected", provider=self.provider_id)
        self.ollama_pull_progress.connect(self._on_ollama_pull_progress)
        self.ollama_pull_finished.connect(self._on_ollama_pull_finished)

        api_base = self._api_base_input.text().strip() if self._api_base_input else ""
        creds = ProviderCredentials(
            api_key=self._api_key_input.text().strip(),
            api_base=api_base or None,
        )
        provider = OllamaProvider()

        pull_result_arity: Final[int] = 2
        pull_failure: Final[bool] = False

        async def _pull() -> tuple[bool, str]:
            """Connect to Ollama and stream pull progress for the selected model.

            Returns:
                tuple[bool, str]: Success flag and the final pull status or
                failure message.
            """
            success: bool = False
            message: str = ""
            try:
                await provider.connect(creds)
            except ProviderError as exc:
                _logger.warning("ollama_pull_connect_failed", model=model_name, error=str(exc))
                return pull_failure, f"Connect failed: {exc}"
            try:
                last_status = ""
                async for status in provider.pull_model(model_name):
                    last_status = status
                    self.ollama_pull_progress.emit(model_name, status)
            except ProviderError as exc:
                _logger.warning("ollama_pull_failed", model=model_name, error=str(exc))
                message = str(exc)
            else:
                success = True
                message = last_status or f"Pulled {model_name}"
            finally:
                await provider.disconnect()
            return success, message

        def _on_success(result: object) -> None:
            """Emit ollama_pull_finished from the async pull result tuple.

            Args:
                result: ``(success, message)`` tuple from the pull coroutine,
                    or an unexpected payload that becomes a failure signal.
            """
            if isinstance(result, tuple) and len(cast("tuple[object, ...]", result)) == pull_result_arity:
                tup = cast("tuple[object, object]", result)
                ok = bool(tup[0])
                msg = tup[1] if isinstance(tup[1], str) else ""
                self.ollama_pull_finished.emit(ok, model_name, msg)
            else:
                self.ollama_pull_finished.emit(pull_failure, model_name, "Unexpected pull result")

        def _on_error(exc: object) -> None:
            """Emit a failed ollama_pull_finished signal for worker errors.

            Args:
                exc: Exception or error payload from the pull worker.
            """
            self.ollama_pull_finished.emit(pull_failure, model_name, str(exc))

        self._set_status(f"Pulling {model_name}...")
        run_bridge_coroutine_async(_pull(), on_success=_on_success, on_error=_on_error, parent=self)

    def get_openrouter_generation(self, generation_id: str) -> None:
        """Look up OpenRouter generation cost info for cost tracking.

        The network round-trip is dispatched on the persistent bridge event
        loop via ``run_bridge_coroutine_async`` so it cannot freeze the GUI
        thread; the outcome is delivered through the
        ``generation_lookup_finished`` signal.

        Args:
            generation_id: The generation ID to look up.
        """
        if self.provider_id != "openrouter":
            self.generation_lookup_finished.emit(_LOOKUP_FAILED, generation_id, "OpenRouter provider is not selected")
            return
        if OpenRouterProvider is None:
            self.generation_lookup_finished.emit(_LOOKUP_FAILED, generation_id, "OpenRouter provider is unavailable")
            return
        api_key = self._api_key_input.text().strip()
        if not api_key:
            self.generation_lookup_finished.emit(_LOOKUP_FAILED, generation_id, "No OpenRouter API key configured")
            return
        self._fetch_openrouter_generation(OpenRouterProvider, api_key, generation_id)

    def _fetch_openrouter_generation(
        self,
        provider_cls: type[_OpenRouterProviderType],
        api_key: str,
        generation_id: str,
    ) -> None:
        """Run the OpenRouter generation lookup coroutine without blocking the GUI thread.

        Args:
            provider_cls: ``OpenRouterProvider`` class to instantiate.
            api_key: OpenRouter API key to authenticate the request.
            generation_id: The generation ID to look up.
        """
        provider = provider_cls()
        creds = ProviderCredentials(api_key=api_key)

        async def _fetch() -> dict[str, Any] | None:
            """Authenticate with OpenRouter and look up generation cost metadata.

            Returns:
                dict[str, Any] | None: Generation payload when found, otherwise
                ``None``.
            """
            try:
                await provider.connect(creds)
                return await provider.get_generation(generation_id)
            finally:
                await provider.disconnect()

        def _on_success(result: object) -> None:
            """Format generation metadata and emit generation_lookup_finished.

            Args:
                result: Generation dict from OpenRouter, or a non-dict payload
                    treated as a not-found outcome.
            """
            found = isinstance(result, dict)
            if found:
                generation_data = cast("dict[str, Any]", result)
                message = "\n".join(f"{k}: {v}" for k, v in generation_data.items())
            else:
                message = f"No data found for generation ID: {generation_id}"
            self.generation_lookup_finished.emit(found, generation_id, message)

        def _on_error(exc: object) -> None:
            """Emit a not-found generation lookup result after a worker error.

            Args:
                exc: Exception or error payload from the generation fetch.
            """
            _logger.debug("openrouter_generation_fetch_failed", generation_id=generation_id, error=str(exc))
            self.generation_lookup_finished.emit(_LOOKUP_FAILED, generation_id, f"No data found for generation ID: {generation_id}")

        run_bridge_coroutine_async(_fetch(), on_success=_on_success, on_error=_on_error, parent=self)

    def get_xpu_optimal_dtype(self) -> str | None:
        """Get optimal dtype for XPU inference.

        Returns:
            str | None: Optimal dtype string or None.
        """
        if get_optimal_dtype_for_xpu is None:
            return None
        try:
            dtype = get_optimal_dtype_for_xpu()
        except (RuntimeError, OSError):
            _logger.debug("xpu_dtype_detection_failed", exc_info=True)
            return None
        else:
            self._xpu_dtype: str | None = dtype
            return dtype


class ModelSelectionDialog(QDialog):
    """Dialog for selecting a specific model from a provider.

    Displays available models with their capabilities and allows
    the user to select one.

    Attributes:
        model_selected: Signal emitted when a model is selected.
    """

    model_selected: ClassVar[pyqtSignal] = pyqtSignal(str)

    def __init__(
        self,
        models: list[ModelInfo],
        current_model: str | None = None,
        provider_name: ProviderName | None = None,
        discovery: ModelDiscovery | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ModelSelectionDialog with available models.

        Args:
            models: List of available models to display.
            current_model: Currently selected model identifier.
            provider_name: Name of the provider these models belong to.
            discovery: Optional model discovery service for filtering and recommendations.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._models = models
        self._current_model = current_model
        self._provider_name = provider_name
        self._discovery = discovery

        self._setup_ui()
        self._populate_models()
        self._update_discovery_status()

        self.setWindowTitle("Select Model")
        self.resize(_DISCOVERY_WIDTH, _DISCOVERY_HEIGHT)

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        self._model_list = QListWidget()
        self._model_list.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self._model_list)

        self._info_label = QLabel()
        self._info_label.setWordWrap(True)
        self._info_label.setObjectName("info_label")
        layout.addWidget(self._info_label)

        self._discovery_status_label = QLabel()
        self._discovery_status_label.setWordWrap(True)
        self._discovery_status_label.setObjectName("discovery_status_label")
        layout.addWidget(self._discovery_status_label)

        self._model_list.currentRowChanged.connect(self._on_model_selected)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _populate_models(self) -> None:
        """Populate the model list."""
        for model in self._models:
            item = QListWidgetItem(model.name)
            item.setData(Qt.ItemDataRole.UserRole, model)
            self._model_list.addItem(item)

            if self._current_model and model.id == self._current_model:
                self._model_list.setCurrentItem(item)

    def _update_discovery_status(self) -> None:
        """Update the discovery status label with the last event for the provider."""
        if self._discovery is None or self._provider_name is None:
            self._discovery_status_label.setText("")
            return

        event: DiscoveryEvent | None = self._discovery.get_last_event(self._provider_name)
        if event is None:
            self._discovery_status_label.setText("No discovery data available.")
            return

        ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        if event.success:
            parts = [f"Last discovery: {ts} — {event.model_count} models found"]
            if event.new_models:
                parts.append(
                    f"New: {', '.join(event.new_models[:_MAX_DISCOVERY_PREVIEW_ITEMS])}"
                    + (" ..." if len(event.new_models) > _MAX_DISCOVERY_PREVIEW_ITEMS else ""),
                )
            if event.removed_models:
                parts.append(
                    f"Removed: {', '.join(event.removed_models[:_MAX_DISCOVERY_PREVIEW_ITEMS])}"
                    + (" ..." if len(event.removed_models) > _MAX_DISCOVERY_PREVIEW_ITEMS else ""),
                )
            self._discovery_status_label.setText(" | ".join(parts))
        else:
            error = event.error_message or "Unknown error"
            self._discovery_status_label.setText(f"Last discovery: {ts} — Failed: {error}")

    def _on_model_selected(self, index: int) -> None:
        """Handle model selection change.

        Args:
            index: Selected model index.
        """
        if index >= 0 and (item := self._model_list.item(index)):
            model: ModelInfo = item.data(Qt.ItemDataRole.UserRole)
            info_parts = [
                f"<b>{model.name}</b>",
                f"ID: {model.id}",
                f"Context: {model.context_window:,} tokens",
            ]
            if model.supports_tools:
                info_parts.append("Supports tool calling")
            if model.supports_vision:
                info_parts.append("Supports vision")

            self._info_label.setText("<br>".join(info_parts))

    def _on_item_double_clicked(self, _item: QListWidgetItem) -> None:
        """Handle double-click on model item.

        Args:
            _item: The double-clicked item (unused, current selection used).
        """
        self._on_accept()

    def _on_accept(self) -> None:
        """Handle dialog acceptance."""
        if current_item := self._model_list.currentItem():
            model: ModelInfo = current_item.data(Qt.ItemDataRole.UserRole)
            self.model_selected.emit(model.id)
            self.accept()

    def get_selected_model(self) -> str | None:
        """Get the selected model ID.

        Returns:
            str | None: Selected model ID or None if nothing selected.
        """
        if current_item := self._model_list.currentItem():
            model: ModelInfo = current_item.data(Qt.ItemDataRole.UserRole)
            return model.id
        return None
