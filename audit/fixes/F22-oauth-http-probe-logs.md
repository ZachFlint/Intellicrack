# F22 — OAuth flows + provider HTTP probe entry logs

## Fix description

Per §2.3, every network call must have a log statement before AND after. The OAuth flow and provider-config HTTP probe / fetch helpers consistently log only failures. The "before" log (`<op>_started`) is missing for ~17 sites.

## Sites to fix

### `src/intellicrack/credentials/oauth.py`

| Line | Context | Suggested log |
|-----:|---------|---------------|
| 756 | `webbrowser.open(auth_url)` in `start_authorization_flow` | `_logger.info("oauth_browser_opened", provider=config.provider.value, auth_url=auth_url)` (or redacted URL if it contains sensitive params) |
| 1233 | `webbrowser.open(auth_url)` in `run_authorization_flow` | Same |
| 849 | `response = await client.post(config.token_url, ...)` token exchange | `_logger.debug("oauth_code_exchange_started", provider=..., token_url=...)` before |
| 1047 | `response = await client.post(config.token_url, ...)` refresh | `_logger.debug("oauth_token_refresh_started", provider=...)` before |
| 1119 | `revoke_response = await client.post(config.revoke_url, ...)` revoke | `_logger.debug("oauth_token_revoke_request_started", provider=...)` before |

### `src/intellicrack/ui/provider_config.py`

#### Connection probes (success path silent)

| Line | Provider | Fix |
|-----:|----------|-----|
| 368-389 | `_test_provider_connection` dispatcher | Add entry log identifying probe target |
| 402-415 | `_test_anthropic` `httpx.Client.get` | `_logger.debug("anthropic_test_started", base_url=...)` before; success log after |
| 433-443 | `_test_openai` | Same pattern |
| 460-470 | `_test_google` | Same |
| 488-493 | `_test_ollama` | Same |
| 511-521 | `_test_openrouter` | Same |
| 538-549 | `_test_huggingface` | Same |
| 601-612 | `_test_grok` | Same |

#### Model-list fetch loops (success path silent)

| Line | Provider | Fix |
|-----:|----------|-----|
| 719-748 | `_fetch_anthropic_models` paginated GET loop | Add per-page debug + overall entry + success summary |
| 755-795 | `_fetch_openai_models` | Same |
| 800-823 | `_fetch_google_models` | Same |
| 826-845 | `_fetch_ollama_models` | Same |
| 848-871 | `_fetch_openrouter_models` | Same |
| 886-908 | `_fetch_huggingface_models` | Same |
| 962-977 | `_fetch_grok_models` | Same |

#### Other workflow events

| Line | Context | Fix |
|-----:|---------|-----|
| 1407-1427 | `refresh_credentials` button-bound | `_logger.warning(...)` on failure (currently debug) |
| 1429-1436 | `create_env_template` button-bound | `_logger.warning(...)` on failure |
| 1438-1446 | `migrate_credentials` button-bound | `.warning(...)` on failure |
| 1500-1512 | `start_oauth_flow` | `_logger.info("oauth_flow_started", provider=...)` on entry |
| 2461-2476 | `_on_connection_tested` triggers `QTimer.singleShot(500, self._auto_refresh_models)` | Log the transition |

#### Recommended pattern: `_log_http_probe(provider, method, url)` helper

Add a small helper to consolidate the 14+ probe/fetch sites:

```python
def _log_http_probe_started(provider: str, method: str, url: str) -> None:
    _logger.debug(f"{provider}_http_probe_started", method=method, url=url)


def _log_http_probe_completed(provider: str, status_code: int, latency_ms: int) -> None:
    _logger.debug(f"{provider}_http_probe_completed", status_code=status_code, latency_ms=latency_ms)
```

## Acceptance criteria

- [ ] 5 oauth.py entry logs added
- [ ] 14 provider_config.py probe/fetch entry+exit logs added
- [ ] (Optional) `_log_http_probe_started/_completed` helper introduced and rolled out
- [ ] User-initiated `refresh_credentials` / `create_env_template` / `migrate_credentials` failure paths log at `warning` not `debug`
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
