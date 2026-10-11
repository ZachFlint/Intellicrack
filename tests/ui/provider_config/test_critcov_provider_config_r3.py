# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass coverage for the import fallbacks and shutdown paths of the provider configuration dialog.

Every test asserts on what a real child interpreter observed. The child imports the real dialog module offscreen with one or more
optional provider modules made unimportable (``sys.modules[name] = None``, the import system's own switch), then drives the real widgets
and workers and prints one JSON object. Four children are shared by the tests through module-scoped fixtures:

* the provider modules ``grok``, ``openrouter``, ``ollama`` and ``local_transformers`` blocked;
* ``xpu_utils`` blocked;
* ``model_loader`` blocked;
* nothing blocked, with the shared bridge event loop closed the way application shutdown leaves it, which is only ever done inside the
  child and never to the pytest process.

A fifth child runs the real OAuth authorization-code flow of the dialog. The ``webbrowser`` registry of that child holds one browser, a
helper script that requests the loopback redirect URL, so the script stands in for the user's browser; a loopback HTTP server stands in
for the authorization server's token endpoint. Nothing leaves the machine and no real browser can start.

Grok is reached through the product's own ``api_base`` setting, pointed at loopback servers from ``tests/_helpers``.
"""

from __future__ import annotations

import os
from typing import Any, Final, cast

import pytest

from tests._helpers.child_python import run_child_json


pytestmark = [pytest.mark.spawns_process]

_CHILD_TIMEOUT_S: Final[float] = 420.0
_CLOSED_LOOP_MESSAGE: Final[str] = "Event loop is closed"
_UNAVAILABLE_LOCAL_MESSAGE: Final[str] = "Local Transformers provider is unavailable (install PyTorch and transformers)"
_XPU_NAMES: Final[tuple[str, ...]] = (
    "check_windows_requirements",
    "clear_xpu_cache",
    "get_optimal_dtype_for_xpu",
    "get_xpu_device_count",
    "get_xpu_device_info",
    "get_xpu_memory_info",
    "is_xpu_available",
)
_KEY: Final[str] = "loop" + "back-" + "credential"
_DROPPED_CONNECTION_MARKERS: Final[tuple[str, ...]] = ("winerror", "disconnected", "reset", "aborted")
_GROK_LISTING_CASES: Final[list[tuple[str, list[object]]]] = [
    ("good", [True, ["grok-a", "grok-b"], "Found 2 Grok models"]),
    ("bad_key", [False, [], "Invalid API key"]),
    ("broken", [False, [], "API error: 500"]),
    ("no_route", [False, [], "API error: 404"]),
]
_OAUTH_VARIANTS: Final[tuple[str, ...]] = ("obtained_with_page", "obtained_without_page", "expiring_token", "empty_access_token")

_PRELUDE: Final[str] = r"""
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

TMP = os.environ["R3_TMP"]
LOCAL = os.path.join(TMP, "LocalAppData")
STATE = os.path.join(LOCAL, "Intellicrack")
os.makedirs(STATE, exist_ok=True)
os.environ["LOCALAPPDATA"] = LOCAL
os.environ["INTELLICRACK_STATE_DIR"] = STATE
from tests._helpers.provider_state import provider_environment_variables

for _name in provider_environment_variables():
    os.environ.pop(_name, None)
for _module in BLOCK:
    sys.modules[_module] = None

import intellicrack.ui.provider_config as pc
from PyQt6.QtCore import QCoreApplication, QThread
from PyQt6.QtWidgets import QApplication, QMessageBox
from intellicrack.core.config import get_config_file
from intellicrack.credentials.provider_settings import PROVIDER_SETTINGS_FILENAME
from intellicrack.ui.panels import async_bridge as ab
from tests._helpers.private_keyring import installed_keyring, private_file_keyring

APP = QApplication([])
SHOWN = []
KEY = "loop" + "back-" + "credential"
NAMES = [
    "LocalTransformersProvider", "OllamaProvider", "OpenRouterProvider", "GrokProvider",
    "check_windows_requirements", "clear_xpu_cache", "get_optimal_dtype_for_xpu", "get_xpu_device_count",
    "get_xpu_device_info", "get_xpu_memory_info", "is_xpu_available", "clear_global_cache", "set_global_cache_size",
]


def _make(kind):
    def _record(*args, **kwargs):
        SHOWN.append([kind] + [str(a) for a in args[1:3]])
        return QMessageBox.StandardButton.Ok
    return staticmethod(_record)


for _kind in ("information", "warning", "critical", "question"):
    setattr(QMessageBox, _kind, _make(_kind))

KEYRING = installed_keyring(private_file_keyring(Path(TMP) / "keyring.cfg"))
KEYRING.__enter__()


def pump(limit, cond=None):
    end = time.monotonic() + limit
    while time.monotonic() < end:
        QCoreApplication.processEvents()
        if cond is not None and cond():
            return True
        time.sleep(0.02)
    return cond is None or bool(cond())


def build(provider_id):
    page = pc.ProviderSettingsWidget(provider_id, None, get_config_file(PROVIDER_SETTINGS_FILENAME), None, None)
    if page._api_key_input.text().strip() or not page._api_key_required():
        pump(15, lambda: page._refresh_worker is not None)
    worker = page._refresh_worker
    if isinstance(worker, QThread):
        worker.wait(60000)
    ab.drain_bridge_workers()
    pump(0.3)
    return page


def none_names():
    return sorted(name for name in NAMES if getattr(pc, name) is None)


def finish(out):
    sys.stdout.flush()
    sys.stdout.write("\n" + json.dumps(out, default=str) + "\n")
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        import coverage

        current = coverage.Coverage.current()
        if current is not None:
            current.stop()
            current.save()
    except Exception:
        pass
    os._exit(0)
"""

_RUNNER: Final[str] = r"""
RESULT = {}
try:
    main(RESULT)
except BaseException:
    import traceback

    RESULT["fatal"] = traceback.format_exc()[-3000:]
finish(RESULT)
"""

_PROVIDERS_BODY: Final[str] = r"""
def grok_cases():
    from tests._helpers.openai_models_server import OpenAIModelsServer

    result = {}
    server = OpenAIModelsServer(model_ids=["grok-b", "grok-a"], accepted_key=KEY)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    dropper = socket.socket()
    dropper.bind(("127.0.0.1", 0))
    dropper.listen(5)
    dropper_port = dropper.getsockname()[1]

    def accept_and_close():
        while True:
            try:
                connection, _ = dropper.accept()
            except OSError:
                return
            connection.close()

    threading.Thread(target=accept_and_close, daemon=True).start()
    result["good_test"] = list(pc.ConnectionTestWorker("grok", KEY, server.base_url)._test_provider_connection())
    result["good_fetch"] = list(pc.ModelRefreshWorker("grok", KEY, server.base_url)._fetch_models())
    result["good_requests"] = [[r.path, r.headers.get("authorization")] for r in server.requests()]
    cases = {
        "bad_key": ("wrong-" + KEY, server.base_url),
        "broken": (KEY, server.broken_base_url),
        "refused": (KEY, "http://127.0.0.1:%d/v1" % dead_port),
        "dropped": (KEY, "http://127.0.0.1:%d/v1" % dropper_port),
        "no_route": (KEY, server.origin + "/nothing"),
    }
    for name, (key, base) in cases.items():
        result[name + "_test"] = list(pc.ConnectionTestWorker("grok", key, base)._test_provider_connection())
        result[name + "_fetch"] = list(pc.ModelRefreshWorker("grok", key, base)._fetch_models())
    dropper.close()
    server.shutdown()
    return result


def non_object(body):
    from tests._helpers.scripted_http_endpoint import ScriptedHttpEndpoint, ScriptedReply

    with ScriptedHttpEndpoint([ScriptedReply(chunks=(body,))]) as endpoint:
        worker = pc.ModelRefreshWorker("grok", KEY, endpoint.base_url + "v1")
        emitted = []
        worker.refresh_finished.connect(lambda ok, models, message: emitted.append([bool(ok), list(models), message]))
        raised = None
        try:
            worker.run()
        except BaseException as exc:
            raised = type(exc).__name__ + ": " + str(exc)
    return {"emitted": emitted, "raised": raised}


def main(out):
    out["none_names"] = none_names()
    out["conn_local"] = list(pc.ConnectionTestWorker("local_transformers", "")._test_provider_connection())
    out["device_info"] = build("local_transformers").get_provider_device_info()
    page = build("openrouter")
    generation = []
    page.generation_lookup_finished.connect(lambda ok, gid, message: generation.append([bool(ok), gid, message]))
    page.get_openrouter_generation("gen-1")
    pump(0.5)
    out["generation"] = generation
    out["grok"] = grok_cases()
    out["list_body"] = non_object(b"[1]")
    out["data_not_objects"] = non_object(b'{"data": [1]}')
    out["data_null"] = non_object(b'{"data": null}')
"""

_LOCAL_FACTS: Final[str] = r"""
def local_facts():
    page = build("local_transformers")
    facts = {}
    facts["combo_items"] = [page._device_combo.itemText(i) for i in range(page._device_combo.count())]
    facts["combo_data"] = page._device_combo.itemData(0)
    facts["mem_text"] = page._xpu_mem_text.text()
    facts["mem_bar"] = page._xpu_mem_bar.value()
    facts["is_xpu_available"] = pc.ProviderSettingsWidget._is_xpu_available()
    facts["read_usage"] = page._read_xpu_memory_usage()
    page._refresh_xpu_memory()
    facts["mem_text_refreshed"] = page._xpu_mem_text.text()
    before = len(SHOWN)
    try:
        page._on_clear_cache()
        facts["clear_error"] = None
    except BaseException as exc:
        facts["clear_error"] = type(exc).__name__ + ": " + str(exc)
    facts["clear_shown"] = SHOWN[before:]
    page._on_check_requirements()
    facts["requirements"] = [page._xpu_warnings_label.text(), page._xpu_warnings_label.property("status")]
    facts["optimal_dtype"] = page.get_xpu_optimal_dtype()
    facts["has_xpu_dtype"] = hasattr(page, "_xpu_dtype")
    before = len(SHOWN)
    page._on_detect_xpu_dtype()
    facts["detect_shown"] = SHOWN[before:]
    facts["dtype_text"] = page._dtype_combo.currentText()
    return facts
"""

_XPU_BODY: Final[str] = (
    _LOCAL_FACTS
    + r"""

def main(out):
    out["none_names"] = none_names()
    out["recommended_models"] = len(pc._recommended_local_models)
    out["facts"] = local_facts()
"""
)

_MODEL_LOADER_BODY: Final[str] = (
    _LOCAL_FACTS
    + r"""

def main(out):
    out["none_names"] = none_names()
    out["recommended_models"] = len(pc._recommended_local_models)
    out["facts"] = local_facts()
    out["fetch_local"] = list(pc.ModelRefreshWorker._fetch_local_transformers_models())
"""
)

_CLOSED_LOOP_BODY: Final[str] = r"""
def main(out):
    from structlog.testing import capture_logs

    loop = ab.ensure_loop()
    loop.call_soon_threadsafe(loop.stop)
    thread = ab._state.thread
    thread.join(10)
    loop.close()
    out["loop_closed"] = loop.is_closed()
    out["conn_local"] = list(pc.ConnectionTestWorker("local_transformers", "")._test_provider_connection())
    out["conn_grok"] = list(pc.ConnectionTestWorker("grok", KEY, "http://127.0.0.1:9/v1")._test_provider_connection())
    out["fetch_grok"] = list(pc.ModelRefreshWorker("grok", KEY, "http://127.0.0.1:9/v1")._fetch_models())
    with capture_logs() as captured:
        dialog = pc.ProviderConfigDialog(None, None)
        pump(15, lambda: any(e.get("event") == "credential_store_load_failed" for e in captured))
        out["store_load_failed"] = [e.get("error") for e in captured if e.get("event") == "credential_store_load_failed"]
    dialog._update_status_timer.stop()
    page = build("ollama")
    finished = []
    page.ollama_pull_finished.connect(lambda ok, name, message: finished.append([bool(ok), name, message]))
    before = len(SHOWN)
    page.pull_ollama_model("tiny")
    pump(15, lambda: bool(finished))
    out["pull_finished"] = finished
    out["pull_shown"] = SHOWN[before:]
"""

_OAUTH_HELPER: Final[str] = r"""
import sys
import urllib.parse
import urllib.request

query = urllib.parse.parse_qs(urllib.parse.urlsplit(sys.argv[1]).query)
redirect = query["redirect_uri"][0]
state = query["state"][0]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
opener.open(redirect + "?code=stand-in-code&state=" + urllib.parse.quote(state), timeout=20).read()
"""

_OAUTH_BODY: Final[str] = (
    r"""
OAUTH_HELPER = """
    + repr(_OAUTH_HELPER)
    + r"""


def main(out):
    import urllib.parse
    import webbrowser

    from PyQt6 import sip
    from structlog.testing import capture_logs

    import intellicrack.credentials.oauth as oauth_module
    import intellicrack.credentials.store as store_module
    from intellicrack.credentials.oauth import OAuthConfig, OAuthProvider
    from tests._helpers.scripted_http_server import ScriptedHttpServer, json_response

    store_holder = getattr(store_module, "_store_holder")
    oauth_holder = getattr(oauth_module, "_OAuthManagerHolder")
    helper = Path(TMP) / "stand_in_browser.py"
    helper.write_text(OAUTH_HELPER, encoding="utf-8")
    name = "r3-stand-in-browser"
    webbrowser.register(name, None, webbrowser.GenericBrowser([sys.executable, str(helper), "%s"]), preferred=True)
    webbrowser._tryorder[:] = [name]
    for registered in list(webbrowser._browsers):
        if registered != name:
            del webbrowser._browsers[registered]
    out["browsers"] = sorted(webbrowser._browsers)
    out["tryorder"] = list(webbrowser._tryorder)
    variants = [
        ("obtained_with_page", "google", {"access_token": "stand-in-access", "token_type": "Bearer"}),
        ("obtained_without_page", "no-such-page", {"access_token": "stand-in-access", "token_type": "Bearer"}),
        ("expiring_token", "google", {"access_token": "stand-in-access", "token_type": "Bearer", "expires_in": 60}),
        ("empty_access_token", "google", {"access_token": "", "token_type": "Bearer"}),
    ]
    done = ("oauth_credentials_obtained", "oauth_credentials_missing", "oauth_flow_failed")
    with ScriptedHttpServer() as token_server:
        token_server.script("POST", "/token", *[json_response(200, payload) for _, _, payload in variants])
        for label, provider_id, _ in variants:
            store_holder.instance = None
            oauth_holder.instance = None
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            config = OAuthConfig(
                provider=OAuthProvider.GOOGLE,
                client_id="stand-in-client",
                client_secret=None,
                authorization_url="http://127.0.0.1:1/authorize",
                token_url=token_server.origin + "/token",
                scopes=("openid",),
                redirect_uri="http://127.0.0.1:%d/callback" % port,
            )
            dialog = pc.ProviderConfigDialog(None, None)
            del SHOWN[:]
            with capture_logs() as captured:
                dialog._run_oauth_flow(provider_id, OAuthProvider.GOOGLE, config)
                pump(90, lambda: any(e.get("event") in done for e in captured))
                pump(1.0)
            events = [str(e.get("event")) for e in captured]
            page = dialog._provider_widgets.get("google")
            exchange = token_server.requests("/token")[-1]
            form = urllib.parse.parse_qs(exchange.body.decode())
            out[label] = {
                "obtained": "oauth_credentials_obtained" in events,
                "missing": "oauth_credentials_missing" in events,
                "failed": "oauth_flow_failed" in events,
                "page_key": page._api_key_input.text(),
                "shown": list(SHOWN),
                "grant_type": form.get("grant_type"),
                "code": form.get("code"),
                "has_verifier": "code_verifier" in form,
            }
            dialog._update_status_timer.stop()
            dialog.close()
            ab.drain_bridge_workers()
            sip.delete(dialog)
        out["token_requests"] = len(token_server.requests("/token"))
"""
)


def _run_child(body: str, block: list[str], factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Run a child interpreter and decode the JSON object it prints.

    Args:
        body: Python source defining ``main(out)``, run after the shared prelude.
        block: Dotted module names the child makes unimportable before it imports the dialog.
        factory: Pytest factory for the child's private state directory.

    Returns:
        dict[str, Any]: The child's JSON object, without a ``fatal`` entry.
    """
    work = factory.mktemp("r3child")
    code = f"BLOCK = {block!r}\n{_PRELUDE}\n{body}\n{_RUNNER}"
    coverage_env = {name: value for name, value in os.environ.items() if name.startswith("COV")}
    result = run_child_json(
        code,
        timeout_s=_CHILD_TIMEOUT_S,
        extra_env={**coverage_env, "R3_TMP": str(work), "QT_QPA_PLATFORM": "offscreen", "NO_PROXY": "*", "no_proxy": "*"},
    )
    assert "fatal" not in result, result.get("fatal")
    return result


def _section(result: dict[str, Any], key: str) -> dict[str, Any]:
    """Fetch a nested JSON object from a child result.

    Args:
        result: The child's result.
        key: Name of the entry.

    Returns:
        dict[str, Any]: The nested object.
    """
    value: object = result[key]
    assert isinstance(value, dict)
    return cast("dict[str, Any]", value)


def _items(result: dict[str, Any], key: str) -> list[Any]:
    """Fetch a JSON array from a child result.

    Args:
        result: The child's result.
        key: Name of the entry.

    Returns:
        list[Any]: The array.
    """
    value: object = result[key]
    assert isinstance(value, list)
    return cast("list[Any]", value)


@pytest.fixture(scope="module")
def providers_child(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Observe the dialog with the grok, openrouter, ollama and local_transformers modules unimportable.

    Args:
        tmp_path_factory: Pytest factory for the child's state directory.

    Returns:
        dict[str, Any]: What the child printed.
    """
    return _run_child(
        _PROVIDERS_BODY,
        [
            "intellicrack.providers.grok",
            "intellicrack.providers.openrouter",
            "intellicrack.providers.ollama",
            "intellicrack.providers.local_transformers",
        ],
        tmp_path_factory,
    )


@pytest.fixture(scope="module")
def xpu_child(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Observe the dialog with the xpu_utils module unimportable.

    Args:
        tmp_path_factory: Pytest factory for the child's state directory.

    Returns:
        dict[str, Any]: What the child printed.
    """
    return _run_child(_XPU_BODY, ["intellicrack.providers.xpu_utils"], tmp_path_factory)


@pytest.fixture(scope="module")
def model_loader_child(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Observe the dialog with the model_loader module unimportable.

    Args:
        tmp_path_factory: Pytest factory for the child's state directory.

    Returns:
        dict[str, Any]: What the child printed.
    """
    return _run_child(_MODEL_LOADER_BODY, ["intellicrack.providers.model_loader"], tmp_path_factory)


@pytest.fixture(scope="module")
def closed_loop_child(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Observe the dialog after the shared bridge event loop was closed, as application shutdown leaves it.

    Args:
        tmp_path_factory: Pytest factory for the child's state directory.

    Returns:
        dict[str, Any]: What the child printed.
    """
    return _run_child(_CLOSED_LOOP_BODY, [], tmp_path_factory)


@pytest.fixture(scope="module")
def oauth_child(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Run four OAuth sign-ins against a stand-in browser and a loopback token endpoint.

    Args:
        tmp_path_factory: Pytest factory for the child's state directory.

    Returns:
        dict[str, Any]: What the child printed.
    """
    return _run_child(_OAUTH_BODY, [], tmp_path_factory)


def test_missing_provider_modules_leave_the_dialog_importable_with_their_names_unset(providers_child: dict[str, Any]) -> None:
    """With four optional provider modules unimportable the dialog still imports and leaves exactly those names unset.

    Args:
        providers_child: What the child with the provider modules blocked printed.
    """
    assert _items(providers_child, "none_names") == ["GrokProvider", "LocalTransformersProvider", "OllamaProvider", "OpenRouterProvider"]


def test_local_transformers_connection_test_reports_a_missing_provider_class(providers_child: dict[str, Any]) -> None:
    """Testing the local backend without its provider class reports it as unavailable instead of raising.

    Args:
        providers_child: What the child with the provider modules blocked printed.
    """
    assert providers_child["conn_local"] == [False, _UNAVAILABLE_LOCAL_MESSAGE]


def test_device_info_without_the_local_provider_class_is_none(providers_child: dict[str, Any]) -> None:
    """Without a registry and without the provider class the local page has no device information to show.

    Args:
        providers_child: What the child with the provider modules blocked printed.
    """
    assert providers_child["device_info"] is None


def test_generation_lookup_reports_an_unavailable_provider(providers_child: dict[str, Any]) -> None:
    """An OpenRouter page without the provider class answers a generation lookup with an unavailable message.

    Args:
        providers_child: What the child with the provider modules blocked printed.
    """
    assert providers_child["generation"] == [[False, "gen-1", "OpenRouter provider is unavailable"]]


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("good", [True, "Connected to Grok API"]),
        ("bad_key", [False, "Invalid API key"]),
        ("broken", [False, "API error: 500"]),
        ("no_route", [False, "API error: 404"]),
        ("refused", [False, "Could not connect to Grok API"]),
    ],
)
def test_grok_connection_test_without_the_provider_class_probes_the_models_route(
    providers_child: dict[str, Any],
    case: str,
    expected: list[object],
) -> None:
    """The direct-HTTP Grok connection test maps each loopback server answer to its documented outcome.

    Args:
        providers_child: What the child with the provider modules blocked printed.
        case: Name of the server scenario.
        expected: The ``(success, message)`` pair the scenario must produce.
    """
    grok = _section(providers_child, "grok")

    assert grok[f"{case}_test"] == expected


def test_grok_connection_test_without_the_provider_class_reports_a_dropped_connection(providers_child: dict[str, Any]) -> None:
    """A server that closes the connection without answering is reported with the transport error text, not as an API answer.

    Args:
        providers_child: What the child with the provider modules blocked printed.
    """
    grok = _section(providers_child, "grok")
    success, message = grok["dropped_test"]

    assert success is False
    assert any(marker in str(message).lower() for marker in _DROPPED_CONNECTION_MARKERS)


def test_grok_fallback_sends_the_key_as_a_bearer_token_to_the_models_route(providers_child: dict[str, Any]) -> None:
    """The direct-HTTP Grok test and listing each request ``/v1/models`` with the key as a bearer token.

    Args:
        providers_child: What the child with the provider modules blocked printed.
    """
    grok = _section(providers_child, "grok")

    assert grok["good_requests"] == [["/v1/models", f"Bearer {_KEY}"]] * 2


@pytest.mark.parametrize(
    ("case", "expected"),
    _GROK_LISTING_CASES,
)
def test_grok_model_listing_without_the_provider_class_reads_the_models_route(
    providers_child: dict[str, Any],
    case: str,
    expected: list[object],
) -> None:
    """The direct-HTTP Grok listing maps each loopback server answer to its documented outcome, with sorted model ids on success.

    Args:
        providers_child: What the child with the provider modules blocked printed.
        case: Name of the server scenario.
        expected: The ``(success, models, message)`` triple the scenario must produce.
    """
    grok = _section(providers_child, "grok")

    assert grok[f"{case}_fetch"] == expected


@pytest.mark.parametrize("case", ["refused", "dropped"])
def test_grok_model_listing_without_the_provider_class_reports_transport_failures(providers_child: dict[str, Any], case: str) -> None:
    """A refused or dropped connection fails the direct-HTTP listing with no models and the transport error text.

    Args:
        providers_child: What the child with the provider modules blocked printed.
        case: Name of the server scenario.
    """
    grok = _section(providers_child, "grok")
    success, models, message = grok[f"{case}_fetch"]
    markers = ("refused",) if case == "refused" else _DROPPED_CONNECTION_MARKERS

    assert success is False
    assert models == []
    assert any(marker in str(message).lower() for marker in markers)


@pytest.mark.parametrize("case", ["list_body", "data_not_objects", "data_null"])
def test_grok_model_listing_with_a_malformed_body_still_finishes_the_refresh(providers_child: dict[str, Any], case: str) -> None:
    """A 200 reply whose body is not a model list ends the refresh as a failure instead of escaping the worker.

    ``ModelRefreshWorker.run`` documents that every outcome emits ``refresh_finished`` so a caller that disabled its model picker gets
    it back; the sibling ``_fetch_by_dialect`` already reports a non-object body as a failure.

    Args:
        providers_child: What the child with the provider modules blocked printed.
        case: Name of the malformed body.
    """
    observed = _section(providers_child, case)

    assert observed["raised"] is None
    assert [(emitted[0], emitted[1]) for emitted in observed["emitted"]] == [(False, [])]


def test_missing_xpu_utils_leaves_every_xpu_helper_unset(xpu_child: dict[str, Any]) -> None:
    """With xpu_utils unimportable the dialog still imports, every helper it takes from there is unset and no recommended models load.

    Args:
        xpu_child: What the child with xpu_utils blocked printed.
    """
    assert set(_XPU_NAMES) <= set(_items(xpu_child, "none_names"))
    assert xpu_child["recommended_models"] == 0


def test_local_page_without_xpu_utils_offers_only_the_cpu(xpu_child: dict[str, Any]) -> None:
    """The device combo of the local page names the missing utilities and carries device index 0.

    Args:
        xpu_child: What the child with xpu_utils blocked printed.
    """
    facts = _section(xpu_child, "facts")

    assert facts["combo_items"] == ["CPU (XPU utils unavailable)"]
    assert facts["combo_data"] == 0


def test_local_page_without_xpu_utils_has_no_xpu_memory_information(xpu_child: dict[str, Any]) -> None:
    """Without xpu_utils no XPU is reported, no usage can be read and the memory text says so.

    Args:
        xpu_child: What the child with xpu_utils blocked printed.
    """
    facts = _section(xpu_child, "facts")

    assert facts["is_xpu_available"] is False
    assert facts["read_usage"] is None
    assert facts["mem_text"] == "XPU memory info not available"
    assert facts["mem_text_refreshed"] == "XPU memory info not available"
    assert facts["mem_bar"] == 0


def test_clearing_caches_without_either_cache_helper_still_reports_success(xpu_child: dict[str, Any]) -> None:
    """With both cache-clearing helpers unset the Clear Cache button neither raises nor skips its confirmation.

    Args:
        xpu_child: What the child with xpu_utils blocked printed.
    """
    facts = _section(xpu_child, "facts")

    assert facts["clear_error"] is None
    assert facts["clear_shown"] == [["information", "Cache", "Model cache and XPU cache cleared"]]


def test_requirements_check_without_xpu_utils_is_reported_as_unavailable(xpu_child: dict[str, Any]) -> None:
    """Check Requirements without the helper shows an idle, unavailable notice.

    Args:
        xpu_child: What the child with xpu_utils blocked printed.
    """
    assert _section(xpu_child, "facts")["requirements"] == ["Requirements check not available", "idle"]


def test_dtype_detection_without_xpu_utils_detects_nothing(xpu_child: dict[str, Any]) -> None:
    """Without xpu_utils there is no optimal dtype, nothing is cached, no message is shown and the dtype choice stays on Auto.

    Args:
        xpu_child: What the child with xpu_utils blocked printed.
    """
    facts = _section(xpu_child, "facts")

    assert facts["optimal_dtype"] is None
    assert facts["has_xpu_dtype"] is False
    assert facts["detect_shown"] == []
    assert facts["dtype_text"] == "Auto"


def test_missing_model_loader_leaves_its_helpers_unset(model_loader_child: dict[str, Any]) -> None:
    """With model_loader unimportable the cache helpers and the local provider are unset and the recommended list is empty.

    Args:
        model_loader_child: What the child with model_loader blocked printed.
    """
    assert _items(model_loader_child, "none_names") == ["LocalTransformersProvider", "clear_global_cache", "set_global_cache_size"]
    assert model_loader_child["recommended_models"] == 0


def test_clearing_caches_without_the_global_cache_helper_still_reports_success(model_loader_child: dict[str, Any]) -> None:
    """Clear Cache skips the missing global cache helper, still clears the XPU side and confirms.

    Args:
        model_loader_child: What the child with model_loader blocked printed.
    """
    facts = _section(model_loader_child, "facts")

    assert facts["clear_error"] is None
    assert facts["clear_shown"] == [["information", "Cache", "Model cache and XPU cache cleared"]]


def test_local_model_listing_without_the_recommended_catalog_reports_none(model_loader_child: dict[str, Any]) -> None:
    """The local Transformers listing has nothing to offer once the recommended catalog failed to load.

    Args:
        model_loader_child: What the child with model_loader blocked printed.
    """
    assert model_loader_child["fetch_local"] == [False, [], "No local Transformers models available"]


def test_closed_bridge_loop_fails_the_local_transformers_connection_test_with_the_loop_error(closed_loop_child: dict[str, Any]) -> None:
    """After shutdown closed the bridge loop the local connection test reports asyncio's own error text.

    Args:
        closed_loop_child: What the child with a closed bridge loop printed.
    """
    assert closed_loop_child["loop_closed"] is True
    assert closed_loop_child["conn_local"] == [False, _CLOSED_LOOP_MESSAGE]


def test_closed_bridge_loop_fails_the_grok_connection_test_with_the_loop_error(closed_loop_child: dict[str, Any]) -> None:
    """After shutdown closed the bridge loop the Grok connection test reports asyncio's own error text.

    Args:
        closed_loop_child: What the child with a closed bridge loop printed.
    """
    assert closed_loop_child["conn_grok"] == [False, _CLOSED_LOOP_MESSAGE]


def test_closed_bridge_loop_fails_the_grok_model_listing_with_the_loop_error(closed_loop_child: dict[str, Any]) -> None:
    """After shutdown closed the bridge loop the Grok model listing fails with no models and asyncio's own error text.

    Args:
        closed_loop_child: What the child with a closed bridge loop printed.
    """
    assert closed_loop_child["fetch_grok"] == [False, [], _CLOSED_LOOP_MESSAGE]


def test_closed_bridge_loop_is_logged_when_the_credential_overview_cannot_load(closed_loop_child: dict[str, Any]) -> None:
    """A dialog built after shutdown logs the credential store load failure with the loop error.

    Args:
        closed_loop_child: What the child with a closed bridge loop printed.
    """
    assert closed_loop_child["store_load_failed"] == [_CLOSED_LOOP_MESSAGE]


def test_closed_bridge_loop_ends_an_ollama_pull_with_the_loop_error(closed_loop_child: dict[str, Any]) -> None:
    """A pull started after shutdown finishes as a failure carrying the loop error and tells the user.

    Args:
        closed_loop_child: What the child with a closed bridge loop printed.
    """
    assert closed_loop_child["pull_finished"] == [[False, "tiny", _CLOSED_LOOP_MESSAGE]]
    assert closed_loop_child["pull_shown"] == [["warning", "Ollama Pull Failed", _CLOSED_LOOP_MESSAGE]]


def test_oauth_child_resolves_only_the_stand_in_browser(oauth_child: dict[str, Any]) -> None:
    """The child that runs the sign-ins can resolve exactly one browser, the stand-in script.

    Args:
        oauth_child: What the OAuth child printed.
    """
    assert oauth_child["browsers"] == ["r3-stand-in-browser"]
    assert oauth_child["tryorder"] == ["r3-stand-in-browser"]


@pytest.mark.parametrize(
    ("variant", "page_key", "obtained"),
    [
        ("obtained_with_page", "stand-in-access", True),
        ("obtained_without_page", "", True),
        ("expiring_token", "", False),
        ("empty_access_token", "", False),
    ],
)
def test_oauth_sign_in_applies_usable_credentials_and_reports_missing_ones(
    oauth_child: dict[str, Any],
    variant: str,
    page_key: str,
    *,
    obtained: bool,
) -> None:
    """A completed sign-in fills the provider's page only when a usable token comes back, and the dialog tells which happened.

    A token that expires within five minutes and an empty token both count as no credentials. A sign-in for an id without a page
    obtains credentials and leaves the Google page untouched.

    Args:
        oauth_child: What the OAuth child printed.
        variant: Name of the sign-in scenario.
        page_key: Text the Google page's key field must hold afterwards.
        obtained: Whether the sign-in must report usable credentials.
    """
    observed = _section(oauth_child, variant)

    assert observed["failed"] is False
    assert observed["obtained"] is obtained
    assert observed["missing"] is not obtained
    assert observed["page_key"] == page_key
    assert observed["shown"] == []


def test_oauth_sign_in_exchanges_the_redirect_code_at_the_token_endpoint(oauth_child: dict[str, Any]) -> None:
    """Every sign-in sends the authorization code from the redirect, with a PKCE verifier, to the token endpoint once.

    Args:
        oauth_child: What the OAuth child printed.
    """
    assert oauth_child["token_requests"] == len(_OAUTH_VARIANTS)
    for variant in _OAUTH_VARIANTS:
        observed = _section(oauth_child, variant)
        assert observed["grant_type"] == ["authorization_code"]
        assert observed["code"] == ["stand-in-code"]
        assert observed["has_verifier"] is True
