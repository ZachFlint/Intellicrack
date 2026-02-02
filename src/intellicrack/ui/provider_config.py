"""Provider configuration dialog for Intellicrack.

This module provides the UI for configuring LLM providers, including
API key management, model selection, and connection settings.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import httpx
from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
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
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.types import ProviderName

from ..core.logging import get_logger
from .resources import IconManager


_logger = get_logger("ui.provider_config")

if TYPE_CHECKING:
    from intellicrack.core.types import ModelInfo
    from intellicrack.providers.base import LLMProviderBase
    from intellicrack.providers.discovery import ModelDiscovery
    from intellicrack.providers.registry import ProviderRegistry

HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401


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
    """

    ENV_VAR_MAPPING: ClassVar[dict[str, str]] = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "google": "GOOGLE_API_KEY",
        "ollama": "OLLAMA_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "huggingface": "HUGGINGFACE_API_TOKEN",
        "grok": "XAI_API_KEY",
    }

    def __init__(self, config_path: Path) -> None:
        """Initialize the credential source detector.

        Args:
            config_path: Path to the saved configuration file.
        """
        self._config_path = config_path
        self._env_file_vars: set[str] = set()
        self._load_env_file_vars()

    def _load_env_file_vars(self) -> None:
        """Load variable names present in .env file."""
        env_paths = [
            Path.cwd() / ".env",
            Path("D:/Intellicrack/.env"),
            Path.home() / ".env",
        ]

        for env_path in env_paths:
            if env_path.exists():
                try:
                    with env_path.open("r", encoding="utf-8") as f:
                        for line in f:
                            stripped = line.strip()
                            if stripped and not stripped.startswith("#") and "=" in stripped:
                                key = stripped.split("=", 1)[0].strip()
                                if key.startswith("export "):
                                    key = key[7:].strip()
                                if key:
                                    self._env_file_vars.add(key)
                    break
                except OSError:
                    continue

    def detect_source(self, provider_id: str, current_key: str) -> str:
        """Detect the source of credentials for a provider.

        Args:
            provider_id: The provider identifier.
            current_key: The currently configured API key.

        Returns:
            Credential source string from CredentialSource constants.
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
            with contextlib.suppress(OSError, json.JSONDecodeError), self._config_path.open("r", encoding="utf-8") as f:
                config = json.load(f)
                if provider_id in config and config[provider_id].get("api_key") == current_key:
                    return CredentialSource.MANUAL
        return CredentialSource.MANUAL

    @staticmethod
    def get_source_color(source: str) -> QColor:
        """Get the display color for a credential source.

        Args:
            source: The credential source string.

        Returns:
            QColor for the source indicator.
        """
        color_map = {
            CredentialSource.ENV_FILE: QColor(34, 139, 34),
            CredentialSource.ENVIRONMENT: QColor(70, 130, 180),
            CredentialSource.MANUAL: QColor(218, 165, 32),
            CredentialSource.NOT_CONFIGURED: QColor(178, 34, 34),
        }
        return color_map.get(source, QColor(128, 128, 128))


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
        """Initialize the connection test worker.

        Args:
            provider_id: The provider identifier.
            api_key: The API key to test.
            api_base: Optional API base URL.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._provider_id = provider_id
        self._api_key = api_key
        self._api_base = api_base

    def run(self) -> None:
        """Run the connection test in a separate thread."""
        try:
            success, message = self._test_provider_connection()
            self.test_finished.emit(success, message)
        except Exception as e:
            self.test_finished.emit(False, f"Connection error: {e}")

    def _test_provider_connection(self) -> tuple[bool, str]:
        """Test the connection to the provider.

        Returns:
            Tuple of (success, message).
        """
        timeout = httpx.Timeout(10.0)

        if self._provider_id == "anthropic":
            return self._test_anthropic(timeout)
        if self._provider_id == "openai":
            return self._test_openai(timeout)
        if self._provider_id == "google":
            return self._test_google(timeout)
        if self._provider_id == "ollama":
            return self._test_ollama(timeout)
        if self._provider_id == "openrouter":
            return self._test_openrouter(timeout)
        if self._provider_id == "huggingface":
            return self._test_huggingface(timeout)
        return False, f"Unknown provider: {self._provider_id}"

    def _test_anthropic(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test Anthropic API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-3-5-haiku-20241022",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "test"}],
                    },
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to Anthropic API"
                if response.status_code == HTTP_UNAUTHORIZED:
                    return False, "Invalid API key"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to Anthropic API"
        except Exception as e:
            _logger.exception("provider_test_failed", extra={"provider": "anthropic", "error": str(e)})
            return False, str(e)

    def _test_openai(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test OpenAI API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        base_url = self._api_base or "https://api.openai.com/v1"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to OpenAI API"
                if response.status_code == HTTP_UNAUTHORIZED:
                    return False, "Invalid API key"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to OpenAI API"
        except Exception as e:
            _logger.exception("provider_test_failed", extra={"provider": "openai", "error": str(e)})
            return False, str(e)

    def _test_google(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test Google Gemini API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    headers={"x-goog-api-key": self._api_key},
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to Google Gemini API"
                if response.status_code == HTTP_BAD_REQUEST:
                    return False, "Invalid API key"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to Google API"
        except Exception as e:
            _logger.exception("provider_test_failed", extra={"provider": "google", "error": str(e)})
            return False, str(e)

    def _test_ollama(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test Ollama connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        base_url = self._api_base or "http://localhost:11434"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(f"{base_url}/api/tags")
                if response.status_code == HTTP_OK:
                    return True, "Connected to Ollama"
                return False, f"Ollama error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to Ollama (is it running?)"
        except Exception as e:
            _logger.exception("provider_test_failed", extra={"provider": "ollama", "error": str(e)})
            return False, str(e)

    def _test_openrouter(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test OpenRouter API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        base_url = self._api_base or "https://openrouter.ai/api/v1"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to OpenRouter API"
                if response.status_code == HTTP_UNAUTHORIZED:
                    return False, "Invalid API key"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to OpenRouter API"
        except Exception as e:
            _logger.exception("provider_test_failed", extra={"provider": "openrouter", "error": str(e)})
            return False, str(e)

    def _test_huggingface(self, timeout: httpx.Timeout) -> tuple[bool, str]:
        """Test HuggingFace Inference API connection.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    "https://huggingface.co/api/models",
                    params={"filter": "text-generation", "limit": 1},
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    return True, "Connected to HuggingFace API"
                if response.status_code == HTTP_UNAUTHORIZED:
                    return False, "Invalid API token"
                return False, f"API error: {response.status_code}"
        except httpx.ConnectError:
            return False, "Could not connect to HuggingFace API"
        except Exception as e:
            _logger.exception("provider_test_failed", extra={"provider": "huggingface", "error": str(e)})
            return False, str(e)


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
        """Initialize the model refresh worker.

        Args:
            provider_id: The provider identifier.
            api_key: The API key for authentication.
            api_base: Optional API base URL.
            provider: Optional connected provider instance for direct model listing.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._provider_id = provider_id
        self._api_key = api_key
        self._api_base = api_base
        self._provider = provider

    def run(self) -> None:
        """Run the model refresh in a separate thread."""
        try:
            success, models, message = self._fetch_models()
            self.refresh_finished.emit(success, models, message)
        except Exception as e:
            self.refresh_finished.emit(False, [], f"Error fetching models: {e}")

    def _fetch_models(self) -> tuple[bool, list[str], str]:
        """Fetch available models from the provider API.

        Returns:
            Tuple of (success, model_list, message).
        """
        if self._provider is not None and self._provider.is_connected:
            try:
                model_infos = asyncio.run(self._provider.list_models())
                if model_ids := sorted(m.id for m in model_infos):
                    return True, model_ids, f"Found {len(model_ids)} models"
            except Exception as exc:
                _logger.warning(
                    "provider_list_models_fallback",
                    extra={"provider": self._provider_id, "error": str(exc)},
                )

        timeout = httpx.Timeout(15.0)

        if self._provider_id == "anthropic":
            return self._fetch_anthropic_models(timeout)
        if self._provider_id == "openai":
            return self._fetch_openai_models(timeout)
        if self._provider_id == "google":
            return self._fetch_google_models(timeout)
        if self._provider_id == "ollama":
            return self._fetch_ollama_models(timeout)
        if self._provider_id == "openrouter":
            return self._fetch_openrouter_models(timeout)
        if self._provider_id == "huggingface":
            return self._fetch_huggingface_models(timeout)
        return False, [], f"Unknown provider: {self._provider_id}"

    def _fetch_anthropic_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch Anthropic models from the /v1/models API with pagination.

        Args:
            timeout: HTTP request timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        fallback_models = [
            "claude-opus-4-20250514",
            "claude-sonnet-4-20250514",
            "claude-3-7-sonnet-20250219",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
            "claude-3-haiku-20240307",
        ]

        if not self._api_key:
            return True, fallback_models, "Anthropic models loaded (defaults)"

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
        }
        base_url = (self._api_base or "https://api.anthropic.com").rstrip("/")
        all_models: list[str] = []
        after_id: str | None = None

        try:
            with httpx.Client(timeout=timeout) as client:
                for _ in range(10):
                    params: dict[str, str | int] = {"limit": 100}
                    if after_id is not None:
                        params["after_id"] = after_id

                    resp = client.get(
                        f"{base_url}/v1/models",
                        headers=headers,
                        params=params,
                    )
                    if resp.status_code == HTTP_UNAUTHORIZED:
                        return True, fallback_models, "Invalid API key, showing defaults"
                    if resp.status_code >= HTTP_BAD_REQUEST:
                        return True, fallback_models, f"API error {resp.status_code}, showing defaults"

                    data = resp.json()
                    all_models.extend(
                        model_id
                        for model_entry in data.get("data", [])
                        if (model_id := model_entry.get("id", ""))
                    )

                    if not data.get("has_more", False):
                        break
                    if last_id := data.get("last_id"):
                        after_id = last_id

                    else:
                        break
        except Exception:
            return True, fallback_models, "API unavailable, showing defaults"
        else:
            if all_models:
                all_models.sort()
                return True, all_models, f"Found {len(all_models)} Anthropic models"
            return True, fallback_models, "No models returned, showing defaults"

    def _fetch_openai_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch OpenAI models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "https://api.openai.com/v1"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["id"] for m in data.get("data", []) if m["id"].startswith(("gpt-4", "gpt-3.5", "o1", "o3"))]
                    models.sort(reverse=True)
                    return True, models[:20], f"Found {len(models)} OpenAI models"
                return False, [], f"API error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)

    def _fetch_google_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch Google Gemini models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    headers={"x-goog-api-key": self._api_key},
                )
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["name"].replace("models/", "") for m in data.get("models", []) if "gemini" in m["name"].lower()]
                    return True, models, f"Found {len(models)} Gemini models"
                return False, [], f"API error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)

    def _fetch_ollama_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch installed Ollama models.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "http://localhost:11434"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(f"{base_url}/api/tags")
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["name"] for m in data.get("models", [])]
                    return True, models, f"Found {len(models)} Ollama models"
                return False, [], f"Ollama error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)

    def _fetch_openrouter_models(self, timeout: httpx.Timeout) -> tuple[bool, list[str], str]:
        """Fetch OpenRouter models from API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        base_url = self._api_base or "https://openrouter.ai/api/v1"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    f"{base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["id"] for m in data.get("data", [])]
                    models.sort()
                    return True, models[:50], f"Found {len(models)} OpenRouter models"
                return False, [], f"API error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)

    def _fetch_huggingface_models(
        self,
        timeout: httpx.Timeout,
    ) -> tuple[bool, list[str], str]:
        """Fetch HuggingFace text-generation models from Hub API.

        Args:
            timeout: HTTP timeout configuration.

        Returns:
            Tuple of (success, model_list, message).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(
                    "https://huggingface.co/api/models",
                    params={
                        "filter": "text-generation-inference",
                        "sort": "downloads",
                        "direction": -1,
                        "limit": 50,
                    },
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                if response.status_code == HTTP_OK:
                    data = response.json()
                    models = [m["id"] for m in data if m.get("pipeline_tag") in {"text-generation", "conversational"}]
                    return (
                        True,
                        models[:30],
                        f"Found {len(models)} HuggingFace models",
                    )
                return False, [], f"API error: {response.status_code}"
        except Exception as e:
            return False, [], str(e)


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
        """Initialize the provider configuration dialog.

        Args:
            provider_registry: Registry containing provider instances.
            model_discovery: Discovery service for model information.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._registry = provider_registry
        self._discovery = model_discovery
        self._provider_widgets: dict[str, ProviderSettingsWidget] = {}
        self._provider_items: dict[str, QListWidgetItem] = {}
        self._current_provider: str | None = None
        self._config_path = Path.home() / ".intellicrack" / "providers.json"
        self._credential_detector = CredentialSourceDetector(self._config_path)

        self._setup_ui()
        self._load_providers()
        self._update_status_timer = QTimer(self)
        self._update_status_timer.timeout.connect(self._refresh_provider_status)
        self._update_status_timer.start(30000)

        self.setWindowTitle("Provider Settings")
        self.resize(800, 550)

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        main_layout = QVBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self._provider_list = QListWidget()
        self._provider_list.setMinimumWidth(200)
        self._provider_list.setMaximumWidth(250)
        self._provider_list.currentRowChanged.connect(self._on_provider_selected)
        left_layout.addWidget(self._provider_list)

        self._active_label = QLabel()
        self._active_label.setWordWrap(True)
        self._active_label.setStyleSheet("QLabel { padding: 8px; background-color: #2d2d2d; border-radius: 4px; }")
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

        self._settings_stack = QStackedWidget()

        splitter.addWidget(left_panel)
        splitter.addWidget(self._settings_stack)
        splitter.setSizes([220, 580])

        main_layout.addWidget(splitter, stretch=1)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Apply
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)

        if apply_button := button_box.button(
            QDialogButtonBox.StandardButton.Apply
        ):
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
        ]

        active_name = self._get_active_provider_name()

        for display_name, provider_id in providers:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, provider_id)

            is_active = provider_id == active_name
            is_connected = self._is_provider_connected(provider_id)
            model_count = self._get_model_count(provider_id)

            self._update_provider_item_display(item, display_name, is_active, is_connected, model_count)

            self._provider_list.addItem(item)
            self._provider_items[provider_id] = item

            widget = ProviderSettingsWidget(
                provider_id,
                self._registry,
                self._config_path,
                self._credential_detector,
                self._discovery,
            )
            widget.connection_tested.connect(self._on_widget_connection_tested)
            self._settings_stack.addWidget(widget)
            self._provider_widgets[provider_id] = widget

        if self._provider_list.count() > 0:
            self._provider_list.setCurrentRow(0)

    @staticmethod
    def _update_provider_item_display(
        item: QListWidgetItem,
        display_name: str,
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

        if is_connected:
            item.setForeground(QColor(34, 139, 34))
        else:
            item.setForeground(QColor(169, 169, 169))

    def _get_active_provider_name(self) -> str | None:
        """Get the name of the currently active provider.

        Returns:
            Provider ID of the active provider or None.
        """
        if self._registry is None:
            return None
        try:
            active = self._registry.active_name
        except Exception:
            return None
        else:
            return active.value if active is not None else None

    def _is_provider_connected(self, provider_id: str) -> bool:
        """Check if a provider is connected.

        Args:
            provider_id: The provider identifier.

        Returns:
            True if the provider is connected.
        """
        if self._registry is None:
            return False
        try:
            provider_name = ProviderName(provider_id.upper())
            provider = self._registry.get(provider_name)
            return provider is not None and getattr(provider, "is_connected", False)
        except Exception:
            return False

    def _get_model_count(self, provider_id: str) -> int:
        """Get the number of available models for a provider.

        Args:
            provider_id: The provider identifier.

        Returns:
            Number of available models.
        """
        if self._discovery is None:
            return 0
        try:
            provider_name = ProviderName(provider_id.upper())
            counts = self._discovery.get_provider_model_count()
            return counts.get(provider_name, 0)
        except Exception:
            return 0

    def _update_active_label(self) -> None:
        """Update the active provider display label."""
        if active_name := self._get_active_provider_name():
            display_names = {
                "anthropic": "Anthropic",
                "openai": "OpenAI",
                "google": "Google Gemini",
                "ollama": "Ollama",
                "openrouter": "OpenRouter",
                "huggingface": "HuggingFace",
            }
            display = display_names.get(active_name, active_name)
            self._active_label.setText(f"<b>Active:</b> {display}")
        else:
            self._active_label.setText("<b>Active:</b> None selected")

    def _on_set_active(self) -> None:
        """Handle set active button click."""
        if self._current_provider is None:
            QMessageBox.warning(self, "No Selection", "Please select a provider first.")
            return

        if self._registry is None:
            QMessageBox.warning(self, "Registry Error", "Provider registry not available.")
            return

        try:
            provider_name = ProviderName(self._current_provider.upper())
            self._registry.set_active(provider_name)
            self._update_active_label()
            self._refresh_provider_status()
            self.active_provider_changed.emit(self._current_provider)
            _logger.info(
                "active_provider_changed",
                extra={"provider": self._current_provider},
            )
        except ValueError:
            QMessageBox.critical(self, "Error", f"Unknown provider: {self._current_provider}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to set active provider: {e}")

    def _refresh_provider_status(self) -> None:
        """Refresh the connection status for all providers."""
        active_name = self._get_active_provider_name()

        for provider_id, item in self._provider_items.items():
            is_active = provider_id == active_name
            is_connected = self._is_provider_connected(provider_id)
            model_count = self._get_model_count(provider_id)

            display_names = {
                "anthropic": "Anthropic",
                "openai": "OpenAI",
                "google": "Google Gemini",
                "ollama": "Ollama",
                "openrouter": "OpenRouter",
                "huggingface": "HuggingFace",
            }
            display_name = display_names.get(provider_id, provider_id.title())

            self._update_provider_item_display(item, display_name, is_active, is_connected, model_count)

    def _on_widget_connection_tested(self, success: bool, _message: str) -> None:
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
            Dictionary mapping provider IDs to their settings.
        """
        settings: dict[str, dict[str, Any]] = {
            provider_id: widget.get_settings()
            for provider_id, widget in self._provider_widgets.items()
        }
        return settings


class ProviderSettingsWidget(QFrame):
    """Widget for configuring a single provider.

    Displays API key input, model selection, connection settings,
    and credential source information for a specific LLM provider.

    Attributes:
        connection_tested: Signal emitted after connection test.
    """

    connection_tested: ClassVar[pyqtSignal] = pyqtSignal(bool, str)

    def __init__(
        self,
        provider_id: str,
        registry: ProviderRegistry | None = None,
        config_path: Path | None = None,
        credential_detector: CredentialSourceDetector | None = None,
        model_discovery: ModelDiscovery | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the provider settings widget.

        Args:
            provider_id: The provider identifier.
            registry: Provider registry for connection testing.
            config_path: Path to configuration file.
            credential_detector: Detector for credential source identification.
            model_discovery: Discovery service for model recommendations.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._provider_id = provider_id
        self._registry = registry
        self._config_path = config_path or Path.home() / ".intellicrack" / "providers.json"
        self._credential_detector = credential_detector
        self._discovery = model_discovery
        self._models: list[ModelInfo] = []
        self._test_worker: ConnectionTestWorker | None = None
        self._refresh_worker: ModelRefreshWorker | None = None

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
        self._api_key_input.setMinimumWidth(280)
        self._api_key_input.textChanged.connect(self._on_api_key_changed)
        api_key_row.addWidget(self._api_key_input)

        self._show_key_btn = QPushButton("Show")
        self._show_key_btn.setMaximumWidth(60)
        self._show_key_btn.setCheckable(True)
        self._show_key_btn.toggled.connect(self._toggle_key_visibility)
        api_key_row.addWidget(self._show_key_btn)

        credentials_layout.addRow("API Key:", api_key_row)

        self._credential_source_label = QLabel()
        self._credential_source_label.setStyleSheet("QLabel { padding: 4px 8px; border-radius: 3px; font-size: 11px; }")
        credentials_layout.addRow("Source:", self._credential_source_label)

        self._api_base_input: QLineEdit | None
        self._org_id_input: QLineEdit | None

        if self._provider_id == "ollama":
            self._api_base_input = QLineEdit()
            self._api_base_input.setText("http://localhost:11434")
            credentials_layout.addRow("API Base URL:", self._api_base_input)
        elif self._provider_id in {"openai", "openrouter"}:
            self._api_base_input = QLineEdit()
            credentials_layout.addRow("API Base URL (optional):", self._api_base_input)
        else:
            self._api_base_input = None

        if self._provider_id == "openai":
            self._org_id_input = QLineEdit()
            credentials_layout.addRow("Organization ID:", self._org_id_input)
        else:
            self._org_id_input = None

        credentials_group.setLayout(credentials_layout)
        layout.addWidget(credentials_group)

        model_group = QGroupBox("Model Settings")
        model_layout = QFormLayout()

        model_row = QHBoxLayout()
        self._model_combo = QComboBox()
        self._model_combo.setMinimumWidth(250)
        model_row.addWidget(self._model_combo)

        self._refresh_models_btn = QPushButton("Refresh")
        self._refresh_models_btn.clicked.connect(self._refresh_models)
        model_row.addWidget(self._refresh_models_btn)
        model_row.addStretch()

        model_layout.addRow("Default Model:", model_row)

        self._recommended_label = QLabel()
        self._recommended_label.setWordWrap(True)
        self._recommended_label.setStyleSheet("QLabel { color: #6a9fb5; font-style: italic; font-size: 11px; }")
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
        layout.addStretch()

    def _get_display_name(self) -> str:
        """Get the display name for the provider.

        Returns:
            Human-readable provider name.
        """
        names = {
            "anthropic": "Anthropic",
            "openai": "OpenAI",
            "google": "Google Gemini",
            "ollama": "Ollama",
            "openrouter": "OpenRouter",
            "huggingface": "HuggingFace",
        }
        return names.get(self._provider_id, self._provider_id.title())

    def _toggle_key_visibility(self, show: bool) -> None:
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

        source = self._credential_detector.detect_source(self._provider_id, api_key)
        color = self._credential_detector.get_source_color(source)

        self._credential_source_label.setText(source)
        self._credential_source_label.setStyleSheet(
            f"QLabel {{ padding: 4px 8px; border-radius: 3px; font-size: 11px; "
            f"background-color: rgba({color.red()}, {color.green()}, {color.blue()}, 0.2); "
            f"color: rgb({color.red()}, {color.green()}, {color.blue()}); }}"
        )

    def _update_recommended_model(self) -> None:
        """Update the recommended model label based on discovery."""
        if self._discovery is None:
            self._recommended_label.setText("")
            return

        try:
            loop: asyncio.AbstractEventLoop | None = None
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                _logger.debug("no_running_event_loop", extra={"provider": self._provider_id})

            if loop is not None and loop.is_running():
                self._recommended_label.setText("")
                return

            if recommended := asyncio.run(
                self._discovery.get_recommended_model(self._provider_id)
            ):
                self._recommended_label.setText(f"Recommended: {recommended.name}")
            else:
                self._recommended_label.setText("")
        except Exception as e:
            _logger.exception("recommended_model_update_failed", extra={"provider": self._provider_id, "error": str(e)})
            self._recommended_label.setText("")

    def _load_settings(self) -> None:
        """Load settings from config file and environment."""
        saved_settings = self._load_from_config()
        _logger.info(
            "provider_settings_loaded",
            extra={"provider": self._provider_id},
        )

        env_vars = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "huggingface": "HUGGINGFACE_API_TOKEN",
        }

        api_key = ""
        if self._provider_id in env_vars:
            env_key = os.environ.get(env_vars[self._provider_id], "")
            config_key = saved_settings.get("api_key", "")
            api_key = config_key or env_key
            if api_key:
                self._api_key_input.setText(api_key)

        if self._provider_id == "ollama":
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

        saved_model = saved_settings.get("default_model", "")
        self._populate_default_models()
        if saved_model:
            idx = self._model_combo.findText(saved_model)
            if idx >= 0:
                self._model_combo.setCurrentIndex(idx)

        self._update_credential_source_display(api_key)
        self._update_recommended_model()

        has_key = bool(self._api_key_input.text().strip())
        if has_key or self._provider_id == "ollama":
            QTimer.singleShot(200, self._auto_refresh_models)

    def _load_from_config(self) -> dict[str, Any]:
        """Load settings from the config file.

        Returns:
            Dictionary of saved settings for this provider.
        """
        if not self._config_path.exists():
            return {}

        try:
            with open(self._config_path, encoding="utf-8") as f:
                all_settings: dict[str, Any] = json.load(f)
                result: dict[str, Any] = all_settings.get(self._provider_id, {})
                return result
        except (json.JSONDecodeError, OSError):
            return {}

    def _populate_default_models(self) -> None:
        """Populate model dropdown with default models."""
        default_models: dict[str, list[str]] = {
            "anthropic": [
                "claude-sonnet-4-20250514",
                "claude-3-5-sonnet-20241022",
                "claude-3-5-haiku-20241022",
                "claude-3-opus-20240229",
            ],
            "openai": [
                "gpt-4o",
                "gpt-4o-mini",
                "gpt-4-turbo",
                "gpt-4",
                "gpt-3.5-turbo",
            ],
            "google": [
                "gemini-2.0-flash-exp",
                "gemini-1.5-pro",
                "gemini-1.5-flash",
                "gemini-1.0-pro",
            ],
            "ollama": [
                "llama3.3:latest",
                "llama3.2:latest",
                "codellama:latest",
                "mistral:latest",
                "deepseek-coder:latest",
            ],
            "openrouter": [
                "anthropic/claude-sonnet-4",
                "anthropic/claude-3.5-sonnet",
                "openai/gpt-4o",
                "google/gemini-pro-1.5",
                "meta-llama/llama-3.3-70b-instruct",
            ],
            "huggingface": [
                "meta-llama/Llama-3.3-70B-Instruct",
                "meta-llama/Llama-3.1-8B-Instruct",
                "mistralai/Mistral-7B-Instruct-v0.3",
                "Qwen/Qwen2.5-72B-Instruct",
                "google/gemma-2-9b-it",
                "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B",
            ],
        }

        models = default_models.get(self._provider_id, [])
        self._model_combo.clear()
        self._model_combo.addItems(models)

    def _refresh_models(self) -> None:
        """Refresh the model list from the provider API."""
        _logger.debug("model_refresh_started", extra={"provider": self._provider_id})
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_loading", 16))
        self._status_label.setText("Refreshing models...")
        self._refresh_models_btn.setEnabled(False)

        api_key = self._api_key_input.text().strip()
        api_base = self._api_base_input.text().strip() if self._api_base_input else None

        if not api_key and self._provider_id != "ollama":
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_warning", 16))
            self._status_label.setText("API key required to refresh models")
            self._refresh_models_btn.setEnabled(True)
            return

        provider = None
        if self._registry is not None:
            with contextlib.suppress(ValueError):
                provider_name = ProviderName(self._provider_id)
                provider = self._registry.get(provider_name)

        self._refresh_worker = ModelRefreshWorker(
            self._provider_id,
            api_key,
            api_base,
            provider=provider,
            parent=self,
        )
        self._refresh_worker.refresh_finished.connect(self._on_models_refreshed)
        self._refresh_worker.start()

    def _auto_refresh_models(self) -> None:
        """Auto-refresh models if no refresh is already running."""
        if self._refresh_worker is not None and self._refresh_worker.isRunning():
            _logger.debug("model_auto_refresh_skipped", extra={"provider": self._provider_id, "reason": "refresh_in_progress"})
            return
        _logger.debug("model_auto_refresh_triggered", extra={"provider": self._provider_id})
        self._refresh_models()

    def _on_models_refreshed(self, success: bool, models: list[str], message: str) -> None:
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
                extra={"provider": self._provider_id, "model_count": len(models)},
            )
            current_model = self._model_combo.currentText()
            self._model_combo.clear()
            self._model_combo.addItems(models)
            idx = self._model_combo.findText(current_model)
            if idx >= 0:
                self._model_combo.setCurrentIndex(idx)
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._status_label.setText(message)
        else:
            _logger.warning(
                "provider_models_refresh_failed",
                extra={"provider": self._provider_id, "error": message or "Failed to refresh models"},
            )
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText(message or "Failed to refresh models")

    def _test_connection(self) -> None:
        """Test the provider connection."""
        _logger.info(
            "provider_connection_test_started",
            extra={"provider": self._provider_id},
        )

        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_loading", 16))
        self._status_label.setText("Testing connection...")
        self._test_btn.setEnabled(False)

        api_key = self._api_key_input.text().strip()
        api_base = self._api_base_input.text().strip() if self._api_base_input else None

        if not api_key and self._provider_id != "ollama":
            _logger.warning(
                "provider_connection_test_failed",
                extra={"provider": self._provider_id, "error": "API key required"},
            )
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText("API key required")
            self._test_btn.setEnabled(True)
            return

        self._test_worker = ConnectionTestWorker(self._provider_id, api_key, api_base, self)
        self._test_worker.test_finished.connect(self._on_connection_tested)
        self._test_worker.start()

    def _on_connection_tested(self, success: bool, message: str) -> None:
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
                extra={"provider": self._provider_id, "status_message": message},
            )
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._status_label.setText(message)
            QTimer.singleShot(500, self._auto_refresh_models)
        else:
            _logger.warning(
                "provider_connection_test_failed",
                extra={"provider": self._provider_id, "error": message},
            )
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
            self._status_label.setText(message)

        self.connection_tested.emit(success, message)

    def get_settings(self) -> dict[str, Any]:
        """Get current settings as a dictionary.

        Returns:
            Dictionary of current settings.
        """
        settings: dict[str, Any] = {
            "enabled": self._enabled_checkbox.isChecked(),
            "api_key": self._api_key_input.text().strip(),
            "default_model": self._model_combo.currentText(),
            "timeout_seconds": self._timeout_spin.value(),
            "max_retries": self._retries_spin.value(),
        }

        if self._api_base_input:
            settings["api_base"] = self._api_base_input.text().strip()

        if self._org_id_input:
            settings["organization_id"] = self._org_id_input.text().strip()

        return settings

    def save_settings(self) -> None:
        """Save current settings to config file and .env file."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)

        all_settings: dict[str, dict[str, Any]] = {}
        if self._config_path.exists():
            try:
                with open(self._config_path, encoding="utf-8") as f:
                    all_settings = json.load(f)
            except (json.JSONDecodeError, OSError):
                all_settings = {}

        settings = self.get_settings()
        if settings.get("api_key"):
            all_settings[self._provider_id] = settings
        elif self._provider_id in all_settings:
            del all_settings[self._provider_id]

        try:
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(all_settings, f, indent=2)
            _logger.info(
                "provider_settings_saved",
                extra={"provider": self._provider_id},
            )
        except OSError as e:
            _logger.exception(
                "provider_settings_save_failed",
                extra={"provider": self._provider_id, "error": str(e)},
            )
            QMessageBox.warning(
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

        env_var_mapping: dict[str, str] = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "ollama": "OLLAMA_API_KEY",
            "huggingface": "HUGGINGFACE_API_TOKEN",
            "grok": "XAI_API_KEY",
        }

        if self._provider_id not in env_var_mapping:
            return

        try:
            from intellicrack.credentials.env_loader import get_credential_loader  # noqa: PLC0415

            loader = get_credential_loader()
            loader.save_to_env_file(env_var_mapping[self._provider_id], api_key)

            if self._provider_id == "ollama" and self._api_base_input:
                host = self._api_base_input.text().strip()
                if host and host != "http://localhost:11434":
                    loader.save_to_env_file("OLLAMA_HOST", host)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Save Warning",
                f"Settings saved but failed to update .env file: {e}",
            )


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
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the model selection dialog.

        Args:
            models: List of available models.
            current_model: Currently selected model ID.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._models = models
        self._current_model = current_model

        self._setup_ui()
        self._populate_models()

        self.setWindowTitle("Select Model")
        self.resize(500, 400)

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
            Selected model ID or None if nothing selected.
        """
        if current_item := self._model_list.currentItem():
            model: ModelInfo = current_item.data(Qt.ItemDataRole.UserRole)
            return model.id
        return None
