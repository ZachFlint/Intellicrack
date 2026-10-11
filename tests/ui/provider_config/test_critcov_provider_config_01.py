# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the helpers, credential-source detector and probe workers of the provider configuration dialog.

Every test drives the real module-level helpers, :class:`CredentialSourceDetector`, :class:`ConnectionTestWorker` and
:class:`ModelRefreshWorker` of :mod:`intellicrack.ui.provider_config`. Per-user state (``providers.json``, ``.env``) is redirected into the
test's temporary directory and every provider endpoint is a loopback server from ``tests/_helpers`` or a port nothing listens on. The
probes whose target host is fixed in the product (Google and HuggingFace over HTTPS) are pointed at a loopback HTTP proxy through the
standard ``HTTPS_PROXY`` variable that ``httpx`` honors, so no packet leaves the machine. Workers are exercised by calling their ``run``
method or their probe methods on the test thread, so no thread outlives a test; the bridge loop's workers are drained in teardown.
"""

from __future__ import annotations

import json
import socket
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QHBoxLayout, QSpinBox
from structlog.testing import capture_logs

import intellicrack.providers.local_transformers as local_transformers_module
import intellicrack.ui.provider_config as provider_config_module
from intellicrack.core.config import get_config_file
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.env_loader import unregister_instance_mapping
from intellicrack.credentials.provider_settings import MODEL_OVERRIDES_KEY, PROVIDER_SETTINGS_FILENAME, ProviderSettingsStore
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import ProviderInstance
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, run_bridge_coroutine
from intellicrack.ui.provider_config import ConnectionTestWorker, CredentialSource, CredentialSourceDetector, ModelRefreshWorker
from tests._helpers.openai_models_server import OpenAIModelsServer
from tests._helpers.provider_endpoint_server import OPENAI_COMPATIBLE_MODELS_PATH, ProviderEndpointServer
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root
from tests._helpers.scripted_http_server import ScriptedHttpServer, json_response
from tests.ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path


pytestmark = pytest.mark.usefixtures("qapp")


_INSTANCE_ID: str = "my-gw"
_KEY: str = "loop" + "back-key-" + "k" * 12
_WRONG_KEY: str = "wrong-" + "w" * 12
_KEY_FIELD: str = "api" + "_key"
_ROUTE_MODELS: str = "/v1/models"
_PUBLIC_PLAINTEXT_BASE: str = "http://gateway.example.com/v1"
_WITHHELD_PREFIX: str = "API key withheld"


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    """Redirect per-user state into the test directory and ignore any proxy configured for the machine.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory.

    Yields:
        Path: The redirected state root.
    """
    isolate_provider_environment(monkeypatch)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    with redirected_state_root(monkeypatch, tmp_path) as root:
        try:
            yield root
        finally:
            unregister_instance_mapping(_INSTANCE_ID)
            _ = drain_bridge_workers()


@pytest.fixture
def endpoint() -> Iterator[ProviderEndpointServer]:
    """Provide a loopback provider endpoint accepting only the test key.

    Yields:
        ProviderEndpointServer: The running server.
    """
    with ProviderEndpointServer(accepted_key=_KEY, model_ids=["grok-3-mini", "grok-3"]) as server:
        yield server


@pytest.fixture
def scripted() -> Iterator[ScriptedHttpServer]:
    """Provide a loopback server answering from per-route scripts.

    Yields:
        ScriptedHttpServer: The running server.
    """
    with ScriptedHttpServer() as server:
        yield server


@pytest.fixture
def broken_listing() -> Iterator[OpenAIModelsServer]:
    """Provide a keyless loopback server whose ``broken_base_url`` listing fails with 500.

    Yields:
        OpenAIModelsServer: The running server.
    """
    with OpenAIModelsServer(model_ids=["listed-model"]) as server:
        yield server


@pytest.fixture
def closed_origin() -> str:
    """Provide the origin of a loopback port nothing is listening on.

    Returns:
        str: ``http://127.0.0.1:<port>`` for a port that was bound and released.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = cast("int", probe.getsockname()[1])
    return f"http://127.0.0.1:{port}"


def _route_https_through(monkeypatch: pytest.MonkeyPatch, proxy_origin: str) -> None:
    """Send every HTTPS request ``httpx`` makes to a loopback proxy.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        proxy_origin: Origin of the loopback proxy.
    """
    monkeypatch.setenv("HTTPS_PROXY", proxy_origin)
    monkeypatch.setenv("https_proxy", proxy_origin)
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")


def _save_instance(instance: ProviderInstance) -> None:
    """Store a provider instance in the redirected ``providers.json``.

    Args:
        instance: The instance to store.
    """
    store = ProviderSettingsStore(get_config_file(PROVIDER_SETTINGS_FILENAME))
    store.write_instance(instance.instance_id, instance.to_mapping())


def _probe(worker: ConnectionTestWorker) -> tuple[bool, str]:
    """Run a connection test's probe on the calling thread.

    Args:
        worker: The worker to run.

    Returns:
        tuple[bool, str]: The probe's ``(success, message)``.
    """
    method = cast("Callable[[], tuple[bool, str]]", getattr(worker, "_test_provider_connection"))
    return method()


def _fetch(worker: ModelRefreshWorker) -> tuple[bool, list[str], str]:
    """Run a model refresh's fetch on the calling thread.

    Args:
        worker: The worker to run.

    Returns:
        tuple[bool, list[str], str]: The fetch's ``(success, models, message)``.
    """
    method = cast("Callable[[], tuple[bool, list[str], str]]", getattr(worker, "_fetch_models"))
    return method()


def _helper(name: str) -> Callable[..., object]:
    """Fetch a private module-level helper of the provider configuration module.

    Args:
        name: The helper's name.

    Returns:
        Callable[..., object]: The helper.
    """
    return cast("Callable[..., object]", getattr(provider_config_module, name))


def test_row_content_width_of_a_row_without_buttons_is_zero() -> None:
    """A layout holding nothing, or only a stretch, needs no width."""
    row_width = _helper("_row_content_width")
    empty = QHBoxLayout()
    assert row_width(empty) == 0

    stretched = QHBoxLayout()
    stretched.addStretch(1)
    assert row_width(stretched) == 0


def test_model_overrides_keep_only_object_entries() -> None:
    """Only the per-model entries that are JSON objects survive; a non-object section yields nothing."""
    overrides = _helper("_model_overrides_from")
    saved = {MODEL_OVERRIDES_KEY: {"alpha": {"context_window": 4096}, "beta": "junk", "gamma": 3, "delta": {}}}

    assert overrides(saved) == {"alpha": {"context_window": 4096}, "delta": {}}
    assert overrides({MODEL_OVERRIDES_KEY: ["alpha"]}) == {}
    assert overrides({}) == {}


def test_saved_context_window_reads_only_positive_integers() -> None:
    """A saved window is returned when it is a positive integer and ``0`` otherwise."""
    window = _helper("_saved_context_window")
    saved = {
        MODEL_OVERRIDES_KEY: {
            "good": {"context_window": 4096},
            "zero": {"context_window": 0},
            "negative": {"context_window": -5},
            "text": {"context_window": "4096"},
            "unset": {},
        },
    }

    assert window(saved, "good") == 4096
    assert window(saved, "zero") == 0
    assert window(saved, "negative") == 0
    assert window(saved, "text") == 0
    assert window(saved, "unset") == 0
    assert window(saved, "missing") == 0
    assert window(saved, "") == 0


def test_probe_key_withheld_uses_the_saved_acknowledgement_when_the_page_gives_none() -> None:
    """With no acknowledgement from the page, the saved instance decides whether the key may travel over plain HTTP."""
    withheld = _helper("_probe_key_withheld")
    unacknowledged = ProviderInstance(instance_id=_INSTANCE_ID, api_base=_PUBLIC_PLAINTEXT_BASE)
    acknowledged = ProviderInstance(instance_id=_INSTANCE_ID, api_base=_PUBLIC_PLAINTEXT_BASE, insecure_transport_acknowledged=True)

    assert withheld(_KEY, _PUBLIC_PLAINTEXT_BASE, acknowledged=None, instance=None) is True
    assert withheld(_KEY, _PUBLIC_PLAINTEXT_BASE, acknowledged=None, instance=unacknowledged) is True
    assert withheld(_KEY, _PUBLIC_PLAINTEXT_BASE, acknowledged=None, instance=acknowledged) is False
    assert withheld(_KEY, _PUBLIC_PLAINTEXT_BASE, acknowledged=True, instance=unacknowledged) is False
    assert withheld(_KEY, _PUBLIC_PLAINTEXT_BASE, acknowledged=False, instance=acknowledged) is True
    assert withheld("", _PUBLIC_PLAINTEXT_BASE, acknowledged=None, instance=None) is False


def test_parse_header_lines_skips_blank_lines_and_lines_without_a_name() -> None:
    """Only ``Name: value`` lines with a non-empty name become headers, in the order written."""
    parse = _helper("_parse_header_lines")
    raw = "X-Team: red\n\n   \nno separator here\n: nameless\n  X-Trace :  a:b  \nX-Empty:\n"

    parsed = cast("dict[str, str]", parse(raw))

    assert list(parsed.items()) == [("X-Team", "red"), ("X-Trace", "a:b"), ("X-Empty", "")]
    assert parse("") == {}


def test_parse_json_object_accepts_objects_and_rejects_everything_else() -> None:
    """Blank text is an empty object, a JSON object is returned, and anything else is ``None``."""
    parse = _helper("_parse_json_object")

    assert parse("") == {}
    assert parse("   \n") == {}
    assert parse('{"a": 1, "b": [2]}') == {"a": 1, "b": [2]}
    assert parse("{not json") is None
    assert parse("[1, 2]") is None
    assert parse("3") is None


def test_timeout_spin_box_leaves_an_offered_value_alone_when_editing_finishes() -> None:
    """Finishing an edit keeps a value the dialog offers and raises one below the smallest real timeout."""
    spin = cast("type[QSpinBox]", getattr(provider_config_module, "_TimeoutSpinBox"))()

    spin.setValue(45)
    spin.editingFinished.emit()
    assert spin.value() == 45

    spin.setValue(5)
    spin.editingFinished.emit()
    assert spin.value() == 10


def test_env_file_scan_reads_names_through_export_and_ignores_comments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Comments, blank lines, lines without ``=`` and nameless assignments add nothing; ``export`` is stripped.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.
    """
    env_path = tmp_path / "scan.env"
    _ = env_path.write_text(
        "# ANTHROPIC_API_KEY=commented-out\n\nOPENAI_ORGANIZATION\n=nameless\nexport OPENAI_API_KEY=exported-value\n   \n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "commented-out")
    monkeypatch.setenv("OPENAI_API_KEY", "exported-value")

    detector = CredentialSourceDetector(tmp_path / "absent.json", env_path)

    assert getattr(detector, "_env_file_vars") == {"OPENAI_API_KEY"}
    assert detector.detect_source("openai", "exported-value") == CredentialSource.ENV_FILE
    assert detector.detect_source("anthropic", "commented-out") == CredentialSource.ENVIRONMENT


def test_env_file_that_cannot_be_opened_yields_no_names(tmp_path: Path) -> None:
    """An ``.env`` path that exists but cannot be read as a file is reported as unparsed and contributes nothing.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env_path = tmp_path / "directory.env"
    env_path.mkdir()

    with capture_logs() as captured:
        detector = CredentialSourceDetector(tmp_path / "absent.json", env_path)
    parse = cast("Callable[[Path], bool]", getattr(detector, "_parse_env_file"))

    assert getattr(detector, "_env_file_vars") == set()
    assert parse(env_path) is False
    assert [entry["path"] for entry in captured if entry.get("event") == "env_file_read_failed"] == [str(env_path)]


def test_detect_source_reports_manual_for_a_key_saved_in_the_config(tmp_path: Path) -> None:
    """A key that only the provider configuration file holds is a manual entry.

    Args:
        tmp_path: Per-test temporary directory.
    """
    config_path = tmp_path / "saved-config.json"
    _ = config_path.write_text(json.dumps({"anthropic": {_KEY_FIELD: _KEY}}), encoding="utf-8")
    detector = CredentialSourceDetector(config_path, tmp_path / "absent.env")

    assert detector.detect_source("anthropic", _KEY) == CredentialSource.MANUAL
    assert detector.detect_source("anthropic", "") == CredentialSource.NOT_CONFIGURED


def test_detect_source_survives_an_unreadable_config_file(tmp_path: Path) -> None:
    """A malformed configuration file is logged and the key is still reported as a manual entry.

    Args:
        tmp_path: Per-test temporary directory.
    """
    config_path = tmp_path / "broken-config.json"
    _ = config_path.write_text("{not json", encoding="utf-8")
    detector = CredentialSourceDetector(config_path, tmp_path / "absent.env")

    with capture_logs() as captured:
        source = detector.detect_source("anthropic", _KEY)

    assert source == CredentialSource.MANUAL
    failures = [entry for entry in captured if entry.get("event") == "config_file_read_failed"]
    assert [entry["config_path"] for entry in failures] == [str(config_path)]


def test_classify_probe_response_maps_each_status() -> None:
    """HTTP 200 is success, the invalid-key status carries its message, and every other status is an API error."""
    classify = cast("Callable[..., tuple[bool, str]]", getattr(ConnectionTestWorker, "_classify_probe_response"))

    assert classify("p", 200, "fine") == (True, "fine")
    assert classify("p", 401, "fine") == (False, "Invalid API key")
    assert classify("p", 500, "fine") == (False, "API error: 500")
    assert classify("p", 400, "fine", invalid_key_status=400, invalid_key_message="bad token") == (False, "bad token")
    assert classify("p", 401, "fine", invalid_key_status=400, invalid_key_message="bad token") == (False, "API error: 401")


def test_run_reports_the_probe_outcome_through_the_signal(endpoint: ProviderEndpointServer) -> None:
    """A finished connection test emits its success flag and message.

    Args:
        endpoint: Loopback provider endpoint.
    """
    worker = ConnectionTestWorker("ollama", "", endpoint.ollama_base_url)
    recorder = SignalRecorder()
    worker.test_finished.connect(recorder)

    worker.run()

    assert recorder.calls == [(True, "Connected to Ollama")]


def test_run_reports_a_malformed_base_url_as_a_connection_error() -> None:
    """A base URL that cannot be parsed makes the probe raise, and the worker reports it instead of dying."""
    worker = ConnectionTestWorker("openai", _KEY, "http://[bad")
    recorder = SignalRecorder()
    worker.test_finished.connect(recorder)

    worker.run()

    assert recorder.calls == [(False, "Connection error: Invalid IPv6 URL")]


def test_connection_test_withholds_the_key_from_a_public_plaintext_base() -> None:
    """A key is not sent to plain HTTP on a public host: the probe fails before any request is made."""
    success, message = _probe(ConnectionTestWorker("openai", _KEY, _PUBLIC_PLAINTEXT_BASE))

    assert success is False
    assert message.startswith(_WITHHELD_PREFIX)


def test_connection_test_withholds_the_key_when_the_saved_instance_is_unacknowledged() -> None:
    """With no acknowledgement from the page, an instance saved without one is not sent the key over public plain HTTP."""
    _save_instance(ProviderInstance(instance_id=_INSTANCE_ID, api_base=_PUBLIC_PLAINTEXT_BASE))

    success, message = _probe(ConnectionTestWorker(_INSTANCE_ID, _KEY))

    assert success is False
    assert message.startswith(_WITHHELD_PREFIX)


def test_anthropic_connection_test_authenticates_and_classifies(endpoint: ProviderEndpointServer) -> None:
    """The Anthropic probe sends the key as ``x-api-key`` and maps 200 and 401 to their messages.

    Args:
        endpoint: Loopback provider endpoint.
    """
    accepted = _probe(ConnectionTestWorker("anthropic", _KEY, f"{endpoint.anthropic_base_url}/"))
    rejected = _probe(ConnectionTestWorker("anthropic", _WRONG_KEY, endpoint.anthropic_base_url))

    assert accepted == (True, "Connected to Anthropic API")
    assert rejected == (False, "Invalid API key")
    sent = endpoint.requests("/anthropic/v1/models")
    assert [request.headers["x-api-key"] for request in sent] == [_KEY, _WRONG_KEY]


def test_anthropic_connection_test_reports_an_unreachable_endpoint(closed_origin: str) -> None:
    """A refused connection is reported as an unreachable Anthropic API.

    Args:
        closed_origin: Origin nothing listens on.
    """
    assert _probe(ConnectionTestWorker("anthropic", _KEY, closed_origin)) == (False, "Could not connect to Anthropic API")


def test_anthropic_connection_test_reports_a_transport_error_message() -> None:
    """A transport error that is not a refused connection is reported with its own message."""
    success, message = _probe(ConnectionTestWorker("anthropic", _KEY, "ftp://127.0.0.1:9"))

    assert success is False
    assert "ftp" in message


def test_openai_connection_test_authenticates_and_classifies(endpoint: ProviderEndpointServer, broken_listing: OpenAIModelsServer) -> None:
    """The OpenAI probe sends a bearer key and maps 200, 401 and 500 to their messages.

    Args:
        endpoint: Loopback provider endpoint.
        broken_listing: Loopback server whose listing fails.
    """
    accepted = _probe(ConnectionTestWorker("openai", _KEY, endpoint.openai_compatible_base_url))
    rejected = _probe(ConnectionTestWorker("openai", _WRONG_KEY, endpoint.openai_compatible_base_url))
    failing = _probe(ConnectionTestWorker("openai", _KEY, broken_listing.broken_base_url))

    assert accepted == (True, "Connected to OpenAI API")
    assert rejected == (False, "Invalid API key")
    assert failing == (False, "API error: 500")
    sent = endpoint.requests(OPENAI_COMPATIBLE_MODELS_PATH)
    assert [request.headers["authorization"] for request in sent] == [f"Bearer {_KEY}", f"Bearer {_WRONG_KEY}"]


def test_openai_connection_test_reports_unreachable_and_transport_failures(closed_origin: str) -> None:
    """A refused connection and an unsupported scheme each fail with their own message.

    Args:
        closed_origin: Origin nothing listens on.
    """
    assert _probe(ConnectionTestWorker("openai", _KEY, closed_origin)) == (False, "Could not connect to OpenAI API")
    success, message = _probe(ConnectionTestWorker("openai", _KEY, "ftp://127.0.0.1:9"))
    assert success is False
    assert "ftp" in message


def test_ollama_connection_test_classifies_status_and_failures(endpoint: ProviderEndpointServer, closed_origin: str) -> None:
    """The Ollama probe maps 200 and 404 to their messages and reports refused and unsupported endpoints.

    Args:
        endpoint: Loopback provider endpoint.
        closed_origin: Origin nothing listens on.
    """
    assert _probe(ConnectionTestWorker("ollama", "", endpoint.ollama_base_url)) == (True, "Connected to Ollama")
    assert _probe(ConnectionTestWorker("ollama", "", endpoint.origin)) == (False, "Ollama error: 404")
    assert _probe(ConnectionTestWorker("ollama", "", closed_origin)) == (False, "Could not connect to Ollama (is it running?)")
    success, message = _probe(ConnectionTestWorker("ollama", "", "ftp://127.0.0.1:9"))
    assert success is False
    assert "ftp" in message


def test_openrouter_connection_test_reports_unreachable_and_transport_failures(closed_origin: str) -> None:
    """The OpenRouter probe reports a refused connection and an unsupported scheme.

    Args:
        closed_origin: Origin nothing listens on.
    """
    assert _probe(ConnectionTestWorker("openrouter", _KEY, closed_origin)) == (False, "Could not connect to OpenRouter API")
    success, message = _probe(ConnectionTestWorker("openrouter", _KEY, "ftp://127.0.0.1:9"))
    assert success is False
    assert "ftp" in message


def test_google_and_huggingface_probes_report_a_refused_proxy(monkeypatch: pytest.MonkeyPatch, closed_origin: str) -> None:
    """With the HTTPS proxy refusing connections, the Google and HuggingFace probes report an unreachable API.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        closed_origin: Origin nothing listens on.
    """
    _route_https_through(monkeypatch, closed_origin)

    assert _probe(ConnectionTestWorker("google", _KEY)) == (False, "Could not connect to Google API")
    assert _probe(ConnectionTestWorker("huggingface", _KEY)) == (False, "Could not connect to HuggingFace API")


def test_google_and_huggingface_probes_report_a_proxy_that_refuses_the_tunnel(
    monkeypatch: pytest.MonkeyPatch,
    scripted: ScriptedHttpServer,
) -> None:
    """A proxy that answers the tunnel request with an error is reported with that error.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        scripted: Loopback server acting as the proxy; it implements no ``CONNECT``.
    """
    _route_https_through(monkeypatch, scripted.origin)

    for provider_id in ("google", "huggingface"):
        success, message = _probe(ConnectionTestWorker(provider_id, _KEY))
        assert success is False
        assert "501" in message


def test_grok_connection_test_requires_a_key() -> None:
    """Without a key the Grok probe fails before contacting anything."""
    assert _probe(ConnectionTestWorker("grok", "")) == (False, "Grok API key required")


def test_grok_connection_test_connects_through_the_provider(endpoint: ProviderEndpointServer) -> None:
    """A key the endpoint accepts connects; a key it rejects is reported as invalid.

    Args:
        endpoint: Loopback provider endpoint.
    """
    accepted = _probe(ConnectionTestWorker("grok", _KEY, endpoint.openai_compatible_base_url))
    rejected = _probe(ConnectionTestWorker("grok", _WRONG_KEY, endpoint.openai_compatible_base_url))

    assert accepted == (True, "Connected to Grok API")
    assert rejected == (False, "Invalid API key")
    sent = endpoint.requests(OPENAI_COMPATIBLE_MODELS_PATH)
    assert [request.headers["authorization"] for request in sent] == [f"Bearer {_KEY}", f"Bearer {_WRONG_KEY}"]


def test_grok_connection_test_reports_a_provider_error(scripted: ScriptedHttpServer) -> None:
    """A request error from the endpoint is reported with the provider's message.

    Args:
        scripted: Loopback server answering the model listing with a 400.
    """
    scripted.script("GET", _ROUTE_MODELS, json_response(400, {"error": {"message": "malformed request body"}}))

    success, message = _probe(ConnectionTestWorker("grok", _KEY, f"{scripted.origin}/v1"))

    assert success is False
    assert message.startswith("Grok API request error:")
    assert "malformed request body" in message


def test_local_transformers_connection_test_reports_the_resolved_backend() -> None:
    """The local test connects a real provider and reports its backend, or why PyTorch is missing."""
    torch_module = getattr(local_transformers_module, "_torch")
    missing_message = cast("str", getattr(local_transformers_module, "_MSG_TORCH_REQUIRED"))

    success, message = _probe(ConnectionTestWorker("local_transformers", ""))

    if torch_module is None:
        assert (success, message) == (False, missing_message)
    else:
        assert success is True
        assert message.startswith("Ready for local inference on ")


@pytest.mark.parametrize(
    ("dialect", "route", "header_name", "header_value"),
    [
        (ApiDialect.MESSAGES, _ROUTE_MODELS, "x-api-key", _KEY),
        (ApiDialect.GEMINI, "/v1beta/models", "x-goog-api-key", _KEY),
        (ApiDialect.CHAT_COMPLETIONS, "/models", "authorization", f"Bearer {_KEY}"),
        (ApiDialect.RESPONSES, "/models", "authorization", f"Bearer {_KEY}"),
    ],
)
def test_instance_connection_test_probes_the_dialect_model_list(
    scripted: ScriptedHttpServer,
    dialect: ApiDialect,
    route: str,
    header_name: str,
    header_value: str,
) -> None:
    """A saved instance is probed at its dialect's model list with that dialect's key header and its own headers.

    Args:
        scripted: Loopback server answering the model list.
        dialect: The instance's wire format.
        route: Where that dialect lists its models.
        header_name: The header that dialect carries the key in.
        header_value: The value that header must carry.
    """
    scripted.script("GET", route, json_response(200, {"data": [], "models": []}))
    _save_instance(
        ProviderInstance(instance_id=_INSTANCE_ID, dialect=dialect, api_base=f"{scripted.origin}/", headers={"X-Team": "red"}),
    )

    result = _probe(ConnectionTestWorker(_INSTANCE_ID, _KEY))

    assert result == (True, f"Connected to {scripted.origin}")
    (request,) = scripted.requests(route)
    assert request.headers[header_name] == header_value
    assert request.headers["x-team"] == "red"


def test_instance_connection_test_needs_a_base_url() -> None:
    """An instance with no saved or supplied base URL cannot be probed."""
    assert _probe(ConnectionTestWorker(_INSTANCE_ID, _KEY)) == (False, "No base URL is configured for this provider instance")


def test_instance_connection_test_classifies_status_and_failures(
    endpoint: ProviderEndpointServer,
    closed_origin: str,
) -> None:
    """Without a saved instance the probe assumes Chat Completions and reports 200, 401, a refusal and a transport error.

    Args:
        endpoint: Loopback provider endpoint.
        closed_origin: Origin nothing listens on.
    """
    base = endpoint.openai_compatible_base_url

    assert _probe(ConnectionTestWorker(_INSTANCE_ID, _KEY, base)) == (True, f"Connected to {base}")
    assert _probe(ConnectionTestWorker(_INSTANCE_ID, _WRONG_KEY, base)) == (False, "Invalid API key")
    assert _probe(ConnectionTestWorker(_INSTANCE_ID, _KEY, closed_origin)) == (False, f"Could not connect to {closed_origin}")
    success, message = _probe(ConnectionTestWorker(_INSTANCE_ID, _KEY, "ftp://127.0.0.1:9"))
    assert success is False
    assert "ftp" in message


def test_refresh_run_reports_a_malformed_base_url_as_an_error() -> None:
    """A base URL that cannot be parsed makes the fetch raise, and the worker reports it through its signal."""
    worker = ModelRefreshWorker("openai", _KEY, "http://[bad")
    recorder = SignalRecorder()
    worker.refresh_finished.connect(recorder)

    worker.run()

    assert recorder.calls == [(False, [], "Error fetching models: Invalid IPv6 URL")]


def test_refresh_lists_the_models_of_a_connected_provider() -> None:
    """A connected provider's own listing is returned sorted, without any key or fallback request."""
    with OpenAIModelsServer(model_ids=["beta-model", "alpha-model"]) as server:
        provider = ConfigurableProvider(ProviderInstance(instance_id=_INSTANCE_ID, api_base=server.base_url, requires_api_key=False))
        _ = run_bridge_coroutine(provider.connect(ProviderCredentials()))
        try:
            result = _fetch(ModelRefreshWorker(_INSTANCE_ID, "", server.base_url, provider=provider))
        finally:
            _ = run_bridge_coroutine(provider.disconnect())

    assert result == (True, ["alpha-model", "beta-model"], "Found 2 models")


def test_refresh_falls_through_when_a_connected_provider_lists_nothing() -> None:
    """An empty listing from a connected provider falls back to listing the endpoint directly."""
    with OpenAIModelsServer(model_ids=[]) as server:
        provider = ConfigurableProvider(ProviderInstance(instance_id=_INSTANCE_ID, api_base=server.base_url, requires_api_key=False))
        _ = run_bridge_coroutine(provider.connect(ProviderCredentials()))
        try:
            result = _fetch(ModelRefreshWorker(_INSTANCE_ID, "", server.base_url, provider=provider))
        finally:
            _ = run_bridge_coroutine(provider.disconnect())

    assert result == (False, [], "Found 0 models")


def test_refresh_withholds_the_key_from_a_public_plaintext_base() -> None:
    """A model refresh does not send a key to plain HTTP on a public host."""
    success, models, message = _fetch(ModelRefreshWorker("openai", _KEY, _PUBLIC_PLAINTEXT_BASE))

    assert success is False
    assert models == []
    assert message.startswith(_WITHHELD_PREFIX)


def test_refresh_dispatches_openrouter_and_grok_to_their_listings(endpoint: ProviderEndpointServer) -> None:
    """The refresh routes OpenRouter and Grok to their own listings and returns the models sorted.

    Args:
        endpoint: Loopback provider endpoint.
    """
    base = endpoint.openai_compatible_base_url

    assert _fetch(ModelRefreshWorker("openrouter", _KEY, base)) == (True, ["grok-3", "grok-3-mini"], "Found 2 OpenRouter models")
    assert _fetch(ModelRefreshWorker("grok", _KEY, base)) == (True, ["grok-3", "grok-3-mini"], "Found 2 Grok models")


def test_refresh_dispatches_google_and_huggingface_through_the_https_proxy(
    monkeypatch: pytest.MonkeyPatch,
    scripted: ScriptedHttpServer,
) -> None:
    """The refresh routes Google and HuggingFace to their fixed HTTPS hosts, here reached through a proxy that refuses the tunnel.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        scripted: Loopback server acting as the proxy; it implements no ``CONNECT``.
    """
    _route_https_through(monkeypatch, scripted.origin)

    for provider_id in ("google", "huggingface"):
        success, models, message = _fetch(ModelRefreshWorker(provider_id, _KEY))
        assert success is False
        assert models == []
        assert "501" in message


def test_refresh_google_reports_a_refused_proxy(monkeypatch: pytest.MonkeyPatch, closed_origin: str) -> None:
    """A refused connection while listing Google models is reported with a message.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        closed_origin: Origin nothing listens on.
    """
    _route_https_through(monkeypatch, closed_origin)

    success, models, message = _fetch(ModelRefreshWorker("google", _KEY))

    assert success is False
    assert models == []
    assert message


def test_refresh_lists_the_recommended_local_models() -> None:
    """Local Transformers needs no endpoint: the refresh returns the curated catalogue, sorted and de-duplicated."""
    success, models, message = _fetch(ModelRefreshWorker("local_transformers", ""))

    assert success is True
    assert {"microsoft/Phi-3-mini-4k-instruct", "TinyLlama/TinyLlama-1.1B-Chat-v1.0"} <= set(models)
    assert models == sorted(set(models))
    assert message == f"Found {len(models)} local models"


def test_refresh_reports_an_empty_local_catalogue(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the curated catalogue holds nothing, the refresh says no local models are available.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(provider_config_module, "_recommended_local_models", [])

    assert _fetch(ModelRefreshWorker("local_transformers", "")) == (False, [], "No local Transformers models available")


def test_refresh_instance_needs_a_base_url() -> None:
    """An instance with no saved or supplied base URL cannot be listed."""
    assert _fetch(ModelRefreshWorker(_INSTANCE_ID, "")) == (False, [], "No base URL is configured for this provider instance")


def test_refresh_instance_rejects_a_model_list_that_is_not_an_object(scripted: ScriptedHttpServer) -> None:
    """A model list that is not a JSON object is reported rather than parsed.

    Args:
        scripted: Loopback server answering the model list with a JSON array.
    """
    scripted.script("GET", "/models", json_response(200, ["alpha", "beta"]))

    result = _fetch(ModelRefreshWorker(_INSTANCE_ID, "", scripted.origin))

    assert result == (False, [], "The model list response was not a JSON object")


def test_anthropic_refresh_requires_a_key() -> None:
    """Without a key the Anthropic listing is not attempted."""
    assert _fetch(ModelRefreshWorker("anthropic", "")) == (False, [], "No Anthropic API key configured")


def test_anthropic_refresh_follows_pagination_and_skips_empty_ids(scripted: ScriptedHttpServer) -> None:
    """Each page is requested after the previous page's last id, and entries without an id are skipped.

    Args:
        scripted: Loopback server answering two pages.
    """
    scripted.script(
        "GET",
        _ROUTE_MODELS,
        json_response(200, {"data": [{"id": "m-b"}, {"id": "m-a"}, {"id": ""}], "has_more": True, "last_id": "m-a"}),
        json_response(200, {"data": [{"id": "m-c"}], "has_more": False}),
    )

    result = _fetch(ModelRefreshWorker("anthropic", _KEY, f"{scripted.origin}/"))

    assert result == (True, ["m-a", "m-b", "m-c"], "Found 3 Anthropic models")
    first, second = scripted.requests(_ROUTE_MODELS)
    assert first.query == {"limit": ["100"]}
    assert second.query == {"limit": ["100"], "after_id": ["m-a"]}
    assert first.headers["x-api-key"] == _KEY
    assert first.headers["anthropic-version"] == "2023-06-01"


def test_anthropic_refresh_stops_when_a_further_page_names_no_last_id(scripted: ScriptedHttpServer) -> None:
    """A page that claims more results but names no last id ends the listing with what was collected.

    Args:
        scripted: Loopback server answering one page.
    """
    scripted.script("GET", _ROUTE_MODELS, json_response(200, {"data": [{"id": "only"}], "has_more": True}))

    result = _fetch(ModelRefreshWorker("anthropic", _KEY, scripted.origin))

    assert result == (True, ["only"], "Found 1 Anthropic models")
    assert len(scripted.requests(_ROUTE_MODELS)) == 1


def test_anthropic_refresh_reads_at_most_ten_pages(scripted: ScriptedHttpServer) -> None:
    """A listing that never ends is cut off after ten pages.

    Args:
        scripted: Loopback server answering endless pages.
    """
    pages = [json_response(200, {"data": [{"id": f"model-{n:02d}"}], "has_more": True, "last_id": f"model-{n:02d}"}) for n in range(12)]
    scripted.script("GET", _ROUTE_MODELS, *pages)

    success, models, message = _fetch(ModelRefreshWorker("anthropic", _KEY, scripted.origin))

    assert success is True
    assert models == [f"model-{n:02d}" for n in range(10)]
    assert message == "Found 10 Anthropic models"
    assert len(scripted.requests(_ROUTE_MODELS)) == 10


def test_anthropic_refresh_reports_rejection_and_http_errors(scripted: ScriptedHttpServer) -> None:
    """A 401 is an invalid key, any other error status is reported with its code, and no models is a failure.

    Args:
        scripted: Loopback server answering one response per refresh.
    """
    scripted.script(
        "GET",
        _ROUTE_MODELS,
        json_response(401, {"error": {"message": "nope"}}),
        json_response(500, {"error": {"message": "down"}}),
        json_response(200, {"data": [], "has_more": False}),
    )

    assert _fetch(ModelRefreshWorker("anthropic", _KEY, scripted.origin)) == (False, [], "Invalid API key")
    assert _fetch(ModelRefreshWorker("anthropic", _KEY, scripted.origin)) == (False, [], "API error 500")
    assert _fetch(ModelRefreshWorker("anthropic", _KEY, scripted.origin)) == (False, [], "No models returned")


def test_anthropic_refresh_reports_an_unreachable_endpoint(closed_origin: str) -> None:
    """A refused connection is reported as the API being unavailable.

    Args:
        closed_origin: Origin nothing listens on.
    """
    success, models, message = _fetch(ModelRefreshWorker("anthropic", _KEY, closed_origin))

    assert success is False
    assert models == []
    assert message.startswith("API unavailable: ")


def test_openai_refresh_reports_http_and_connection_failures(broken_listing: OpenAIModelsServer, closed_origin: str) -> None:
    """A failing listing is reported with its status and a refused connection with a message.

    Args:
        broken_listing: Loopback server whose listing fails.
        closed_origin: Origin nothing listens on.
    """
    assert _fetch(ModelRefreshWorker("openai", _KEY, broken_listing.broken_base_url)) == (False, [], "API error: 500")

    success, models, message = _fetch(ModelRefreshWorker("openai", _KEY, closed_origin))
    assert success is False
    assert models == []
    assert message
