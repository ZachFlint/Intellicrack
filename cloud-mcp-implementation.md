# Cloud implementation brief — third-party MCP server support (Intellicrack)

You are implementing an approved plan in the Intellicrack repository
(`ZachFlint/Intellicrack`), on a new branch `feat/mcp-client` cut from `main`
at merge commit `c977291b`.

**Your role is code only.** A separate local session owns every test, every
quality gate, and all environment-bound verification. Write the implementation;
do not write tests and do not claim anything is verified.

---

## 0. Environment constraints — read before doing anything

Your VM is Linux. The project is Windows-first. Several things you would
normally reach for **do not work here**:

- **`pixi` will not work.** `pyproject.toml` sets `workspace.platforms = ["win-64"]`
  and `pixi.lock` contains only win-64 entries. Do not try to fix this, and
  **do not edit `workspace.platforms` or `pixi.lock`.**
- **`ruff` is your one usable gate.** Install it standalone (`pip install ruff`)
  — it needs no project dependencies. Every file you touch must end
  `ruff check` clean using the repo's own config.
- **`basedpyright` will be noisy here** because third-party dependencies and the
  `typings/` stubs resolve out of the win-64 environment you do not have. Run it
  for obvious self-inflicted errors, but **do not chase missing-import findings
  and do not restructure code to silence them.** The local session runs it
  authoritatively.
- **`pytest` cannot run at all.** A repo hook blocks host pytest, and the test
  sandbox is a **Windows Server container** (`docker/Dockerfile.windows`) whose
  runner aborts unless Docker is on its Windows engine. Never report a test as
  passing.
- **You can read the MCP SDK.** `mcp` 2.2.0 and `mcp_types` 2.2.0 are pure
  Python and pip-installable on Linux (`pip install "mcp>=2.2.0,<3"`) purely so
  you can read the source and confirm signatures. Do not add, remove or
  re-pin the dependency — it is already declared at `pyproject.toml:792`.
- **Never modify** the `[tool.basedpyright]` section of `pyproject.toml`,
  `pyrightconfig.json`, the pydoclint/pydocstyle configuration, `pixi.lock`, or
  `requirements.txt` (generated). These are locked.

Line numbers below were verified against `c977291b` on 2026-09-18. They drift as
you edit — treat them as starting points and re-locate symbols by name.

---

## 1. Ground rules (non-negotiable)

- **No placeholders, stubs, mocks, simulated behaviour, hardcoded responses, or
  TODO markers.** Every function performs its real operation. If something
  cannot be completed, leave existing working code in place and say so in your
  summary rather than shipping a stub.
- **Full type annotations everywhere**, written to be basedpyright-correct.
- **Never use any suppression**: no `# type: ignore`, no `# pyright: ignore`, no
  `# noqa`, no inline disables of any kind. Fix the actual error.
- **Google-style docstrings** on every module, class, function and method,
  matching the signature exactly — parameters, types, returns, raises, yields.
  `pydoclint` and `pydocstyle` run locally with zero tolerance.
- **No comments** unless the code genuinely cannot be understood without one.
  **No emojis** anywhere.
- **Never delete a method binding.** If something is missing, create a real,
  functional implementation.
- **Windows compatibility is the priority platform** even though you are on
  Linux. Process launch, path handling, and teardown must be correct on Windows
  first.
- **SOLID / DRY / KISS.** Reuse what exists (§2) rather than building parallel
  machinery.
- Structured logging via `intellicrack.core.logging.get_logger(__name__)` into a
  module-level `_logger`, matching the surrounding modules.

---

## 2. Repository state you are starting from

PR #409 merged on 2026-09-18 (`c977291b`, 192 files) and **already built the
seam you are plugging into**. Read these before writing anything.

### 2.1 The external-tool seam — build on it, do not duplicate it

`src/intellicrack/core/tools.py`:

```python
ExternalToolExecutor = Callable[[str, dict[str, Any]], Awaitable[object]]   # :38
```

It receives **the canonical dotted function name** and the parsed arguments, and
returns either a plain value or a `list[ToolResultPart]`.

```python
class ExternalToolRegistry:                 # :60
    def register(self, namespace: str, executor: ExternalToolExecutor) -> None   # :80
    def unregister(self, namespace: str) -> bool                                  # :101
    def get(self, namespace: str) -> ExternalToolExecutor | None                  # :116
    def namespaces(self) -> list[str]                                             # :129
```

`register` lower-cases the namespace and requires
`key.replace("_","").replace("-","").isalnum()` — **dots are rejected** — and
refuses any namespace in `RESERVED_TOOL_NAMESPACES`
(`bridges/schemas.py:59`, = every `ToolName` value).

`ToolRegistry.external_tools` (`:437`) exposes it; `_execute_external` (`:473`)
runs the call, converts exceptions to `ToolError`, and **already emits the audit
record** via `log_tool_call(tool_name=namespace, function_name=..., arguments=...,
duration_ms=..., success=...)`. `execute_tool_call` (`:969`) resolves a bridge
first and falls through to the external registry at `:996`.

Its own docstring says: *"An MCP client is the obvious first tenant."*

### 2.2 The wire contract — already complete

- `ToolFunction.input_schema: dict[str, Any] | None` (`core/types.py:1726`) —
  raw JSON Schema 2020-12. When set it is authoritative and `parameters` is
  ignored. **Pass MCP `inputSchema` through verbatim; never flatten it into
  `ToolParameter`.**
- `ToolDefinition.tool_name: str` (`:1740`) — an open namespace, documented for
  externally-sourced tools.
- `ToolResult` (`:496`) carries
  `content: list[ToolResultPart] | None` and `is_error: bool`.
  Parts (`:381`–`:453`, all `@dataclass(frozen=True, slots=True)`):

```python
TextResultPart(text: str)
ImageResultPart(data: str, mime_type: str)
AudioResultPart(data: str, mime_type: str)
ResourceLinkPart(uri: str, name: str | None, mime_type: str | None, description: str | None)
EmbeddedResourcePart(uri: str, text: str | None, data: str | None, mime_type: str | None)
StructuredResultPart(content: dict[str, Any])
```

- `bridges/json_schema.py` already reduces raw JSON Schema per dialect
  (`$ref` inlining, keyword filtering). You do not touch it.
- `providers/tool_names.py` `to_wire_name` / `from_wire_name` already handle
  names containing `__` and names over 64 chars via a registered blake2b
  fallback with collision detection.

### 2.3 Other infrastructure to reuse

- `ui/panels/async_bridge.py` — persistent background asyncio loop:
  `ensure_loop()`, `run_bridge_coroutine`, `run_bridge_coroutine_async`,
  `shutdown_bridge_loop()`, `worker_is_running`, `discard_worker`.
- `credentials/store.py` — `CredentialStore`, now **`provider: str`-keyed**:
  `async get(provider) -> ProviderCredentials | None`, `async set(provider, credentials, ...)`,
  `async delete(provider) -> bool`.
- `credentials/oauth.py` — `OAuthManager`, `OAuthCallbackServer` (loopback),
  `generate_pkce_pair`, `OAuthToken`.
- `core/config.py` — `get_config_dir()` → `<state_root>/.intellicrack/`,
  `get_config_path(filename)`.
- `core/logging.py` — `get_logger`, `log_tool_call`.
- Settings-dialog pattern: `ui/provider_config.py`, `ui/tool_config.py`.
  Chat UI: `ui/chat.py`. Confirmation: `ui/confirmation_dialog.py`.

### 2.4 What is still closed (this is your work)

1. No MCP client exists anywhere.
2. `ToolRegistry.get_tool_definitions()` (`:932`) iterates `self._bridges.values()`
   only — **external definitions never reach the LLM**. The merge shipped the
   executor seam but no definition seam.
3. `classify_tool_call` (`orchestrator.py:652`) does `ToolName(tool_name.lower())`
   → MCP resolves to `"unknown"` → treated as destructive. That deny-by-default
   posture is correct and must be preserved; it needs a trust-gated branch.
4. `Session.tool_states: dict[ToolName, ToolState]` (`session.py:342`) is
   deserialized with `ToolName(k)` (`:739`, `:1209`). **Writing an MCP id there
   makes session load raise `ValueError`.**
5. `ToolConfirmationDialog._remembered_decisions` (`confirmation_dialog.py:54`)
   is keyed `(tool_name, function_name)` with no generation component.
6. `trim_messages_to_context_window` (`orchestrator.py:2036`) sums only
   `m.content`. Signature is `(messages, context_window, *, tokenizer: str | None)`.

---

## 3. SDK facts you must code against (verified — several contradict the docs)

- Version constants live in **`mcp_types.version`**, not `mcp.types`:
  `MODERN_PROTOCOL_VERSIONS == ("2026-07-28",)`,
  `HANDSHAKE_PROTOCOL_VERSIONS == ("2024-11-05","2025-03-26","2025-06-18","2025-11-25")`.
- `mcp.Client(server, *, mode="auto", client_info, elicitation_callback,
  sampling_callback, logging_callback, read_timeout_seconds,
  input_required_max_rounds=10, extensions, cache, ...)`. `mode` accepts
  `"legacy"`, `"auto"`, or a member of `MODERN_PROTOCOL_VERSIONS`.
  `server` accepts a `StdioServerParameters`, a URL string, or **any async
  context manager yielding `(read_stream, write_stream)`**
  (`mcp/client/client.py:93` `_connect_transport`).
- **`StreamableHTTPTransport.__init__` takes only `url`** — it has no headers or
  auth parameter. Headers and auth attach to an `httpx2.AsyncClient` handed to
  the module-level async context manager
  `streamable_http_client(url, http_client=..., terminate_on_close=...)`
  (`mcp/client/streamable_http.py:681`). Build the client with
  `mcp.shared._httpx_utils.create_mcp_http_client(headers=..., timeout=..., auth=...)`
  where `auth` is an `httpx2.Auth` — `OAuthClientProvider` implements it.
  **The transport is `httpx2`, not `httpx`.** The SDK follows redirects only
  within the endpoint's origin and ignores `follow_redirects`.
- `mcp.client.stdio`: `stdio_client`,
  `StdioServerParameters(command, args, env, cwd, encoding, encoding_error_handler)`,
  `create_windows_process`, `terminate_windows_process_tree`, `close_process_job`.
- `mcp.types.Tool` fields: `name, title, description, input_schema, execution,
  output_schema, icons, annotations, meta`.
  `ListToolsResult`: `meta, ttl_ms, cache_scope, next_cursor, tools, result_type`.
  `CallToolResult`: `meta, content, structured_content, is_error, result_type`.
  `ToolAnnotations`: `title, read_only_hint, destructive_hint, idempotent_hint,
  open_world_hint`.
- `mcp.client.auth`: `OAuthClientProvider`, `TokenStorage`, `PKCEParameters`;
  `mcp.client.auth.oauth2.create_client_info_from_metadata_url` (CIMD),
  `credentials_match_issuer` (RFC 9207),
  `build_protected_resource_metadata_discovery_urls` (RFC 9728).
- **`FastMCP` does not exist in mcp 2.x** — it is `mcp.server.mcpserver.MCPServer`.
- No tasks extension in the 2.0.x line; client-side DPoP and jwt-bearer are
  unimplemented. Phase 3's tasks item is therefore **not started**.

---

## 4. Standards to implement against

- Spec 2026-07-28 — <https://modelcontextprotocol.io/specification/2026-07-28/changelog>
- Tools — <https://modelcontextprotocol.io/specification/2026-07-28/server/tools>
- Authorization — <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>
- Security best practices — <https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices>
- SEP-1024 local-server consent — <https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-.md>
- OWASP MCP cheat sheet — <https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html>
- VS Code `mcp.json` — <https://code.visualstudio.com/docs/agents/reference/mcp-configuration>

Binding requirements drawn from them:

- A human MUST be able to deny any tool call; the UI shows which tools are
  exposed and the full arguments before calling.
- Tool annotations are **untrusted** unless the server is trusted.
- Tool names are 1–128 chars over `[A-Za-z0-9_.-]`; aggregators **prefix by
  server identity** because server names are not unique.
- Before launching a local server: show the **exact untruncated command** with
  every argument, flag dangerous patterns, warn it runs with the client's
  privileges, require affirmative consent, allow cancel.
- Re-prompt for consent when a server's tool definitions change.
- stdio servers **SHOULD NOT** use OAuth — they take credentials from the
  environment. OAuth is for HTTP servers only.
- Per-server scoped credentials; never share a token between servers.

---

## 5. Architecture — the chosen design (do not redesign)

**A. Naming.** Canonical MCP tool name is `mcp-<serverId>.<mcpToolName>`.
Namespace is `mcp-<serverId>`; `serverId` is validated
`^[a-z0-9][a-z0-9-]{0,31}$`. Hyphen is deliberate: it can never participate in
the `.`↔`__` wire separator, so the namespace segment can never produce an
ambiguous wire name. `<mcpToolName>` is used **verbatim** and may contain dots —
`execute_tool_call`'s `split(".", maxsplit=1)[-1]` and
`_split_tool_function_name` both return the whole remainder, so multi-dot names
route correctly with **no change to either splitter**. The executor receives the
canonical dotted name and strips the `mcp-<serverId>.` prefix.

**B. Identity.** Use the shipped plain `str` namespace on `ToolDefinition`. Do
**not** introduce a `ToolSource` dataclass or a `ToolSourceProvider` protocol —
both were considered and rejected because `main` already chose the `str`
namespace and the `ExternalToolRegistry`.

**C. Classification.** An MCP call is `read_only` **only if** the server is
trusted **and** `annotations.read_only_hint` is true; otherwise `destructive`.

**D. Approvals.** Keyed `(namespace, function_name, generation)` where
`generation` is a stable hash over the server's sorted tool list. Scopes are
once / session / always.

**E. Session state.** MCP state goes in a new `Session.mcp_servers`, never in
`tool_states`. `Session.loaded_tools` is reused **unchanged**.

**F. Config.** `<config_dir>/mcp.json`. VS Code `servers` shape is native;
`mcpServers` is accepted on import. **No secrets in the file** — `${input:id}`
resolves from the keyring.

**G. Lifetime.** Connections are app-lifetime, not conversation-lifetime (per
spec, a stdio process is not a session), owned by the manager on the existing
`async_bridge` loop.

**H. Ordering.** MCP definitions are emitted **after** the meta-tool and core
tools so `_enforce_tool_count_cap` can never truncate tool discovery away.

**I. Enablement.** Tools are off until enabled; per-server and per-tool toggles.

**J. Wire-name warm-up.** Every MCP tool must be pushed through
`to_wire_name` at registration time, before any history replay, so the reverse
registry is warm.

---

## 6. The complete code inventory

Everything below is code you write. Signatures are binding; docstrings are
required on all of them.

### 6.1 New package `src/intellicrack/mcp/`

#### `mcp/__init__.py`

Re-export the public surface: `McpServerConfig`, `McpConfigStore`,
`McpConnectionManager`, `McpToolSource`, `McpError` and friends.

#### `mcp/errors.py`

```python
class McpError(IntellicrackError)
class McpConfigError(McpError)
class McpConnectionError(McpError)
class McpConsentDeniedError(McpError)
class McpProtocolError(McpError)
class McpAuthError(McpError)
```

#### `mcp/config.py`

```python
SERVER_ID_PATTERN: re.Pattern[str]                       # ^[a-z0-9][a-z0-9-]{0,31}$
MCP_CONFIG_FILENAME: str                                 # "mcp.json"
NAMESPACE_PREFIX: str                                    # "mcp-"

class McpTransportKind(enum.Enum):  STDIO / HTTP / SSE

@dataclass(frozen=True, slots=True)
class StdioServerSpec:
    command: str
    args: tuple[str, ...] = ()
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)   # values may be ${input:id}
    env_file: str | None = None

@dataclass(frozen=True, slots=True)
class HttpServerSpec:
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    query: Mapping[str, str] = field(default_factory=dict) # API key / tool-set selection
    oauth_client_id: str | None = None
    oauth_metadata_url: str | None = None                  # CIMD document URL

@dataclass(frozen=True, slots=True)
class McpInputSpec:
    id: str
    description: str
    password: bool = False

@dataclass(frozen=True, slots=True)
class McpSandboxSpec:
    enabled: bool = False
    allow_write: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class McpServerConfig:
    server_id: str
    kind: McpTransportKind
    stdio: StdioServerSpec | None = None
    http: HttpServerSpec | None = None
    enabled: bool = False                                  # off until enabled
    disabled_tools: frozenset[str] = frozenset()
    sandbox: McpSandboxSpec = McpSandboxSpec()
    request_timeout_s: float = 60.0

    @property
    def namespace(self) -> str: ...                        # f"mcp-{self.server_id}"
    def validate(self) -> None: ...                        # raises McpConfigError

@dataclass(frozen=True, slots=True)
class McpConfigDocument:
    servers: tuple[McpServerConfig, ...]
    inputs: tuple[McpInputSpec, ...]

class McpConfigStore:
    def __init__(self, path: Path | None = None) -> None
    def load(self) -> McpConfigDocument
    def save(self, document: McpConfigDocument) -> None
    def import_document(self, raw: str) -> McpConfigDocument
    @staticmethod
    def parse_document(data: Mapping[str, Any]) -> McpConfigDocument
    @staticmethod
    def serialize_document(document: McpConfigDocument) -> dict[str, Any]
```

`parse_document` accepts **both** a `servers` root and an `mcpServers` root and
normalizes them. It infers `type` when absent (`command` ⇒ stdio, `url` ⇒ http).
It **rejects** any config whose `env`/`headers` value looks like a literal
secret rather than a `${input:id}` reference — raise `McpConfigError` naming the
field. Round-tripping must be field-identical.

#### `mcp/secrets.py`

```python
MCP_SECRET_NAMESPACE: str                                  # "mcp"

class McpSecretResolver:
    def __init__(self, store: CredentialStore) -> None
    async def resolve(self, template: str) -> str          # expands ${input:id}
    async def resolve_mapping(self, values: Mapping[str, str]) -> dict[str, str]
    async def set_input(self, input_id: str, value: str) -> None
    async def delete_input(self, input_id: str) -> bool
    async def has_input(self, input_id: str) -> bool
```

Backed by `CredentialStore` with provider key `f"mcp:input:{input_id}"`, storing
the value in `ProviderCredentials.api_key`. An unresolvable reference raises
`McpConfigError` — **never** silently expands to an empty string.

#### `mcp/transport.py`

```python
class McpTransport(Protocol):
    async def __aenter__(self) -> tuple[Any, Any]: ...
    async def __aexit__(self, *exc: object) -> None: ...

def build_stdio_parameters(spec: StdioServerSpec, env: Mapping[str, str]) -> StdioServerParameters

@asynccontextmanager
async def open_http_transport(
    spec: HttpServerSpec, *, headers: Mapping[str, str], auth: httpx2.Auth | None, timeout_s: float,
) -> AsyncIterator[tuple[Any, Any]]
```

`open_http_transport` composes the query parameters onto the URL, builds the
client with `create_mcp_http_client(headers=..., timeout=..., auth=...)`, and
yields from `streamable_http_client(url, http_client=client)`.
`build_stdio_parameters` must **reject shell metacharacters** in `command`
(`&`, `|`, `;`, backtick, `$(`, newline) with `McpConfigError`, and resolve argv
without a shell.

#### `mcp/catalog.py`

```python
@dataclass(frozen=True, slots=True)
class McpToolEntry:
    name: str                                             # server's own name, verbatim
    canonical_name: str                                   # mcp-<id>.<name>
    title: str | None
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: ToolAnnotations | None

@dataclass(frozen=True, slots=True)
class McpToolCatalog:
    server_id: str
    entries: tuple[McpToolEntry, ...]
    generation: str
    fetched_at: datetime
    ttl_ms: int | None
    cache_scope: str | None

    def is_fresh(self, now: datetime) -> bool
    def entry(self, canonical_name: str) -> McpToolEntry | None

def compute_generation(entries: Sequence[McpToolEntry]) -> str
async def fetch_catalog(client: Client, server_id: str) -> McpToolCatalog
```

`fetch_catalog` follows `next_cursor` until exhausted, preserves server order,
and records `ttl_ms` / `cache_scope`. `compute_generation` is a blake2b hex
digest over each entry's sorted `(name, description, canonical JSON of
input_schema, annotations)` — stable across processes.

#### `mcp/connection.py`

```python
class McpHealth(enum.Enum):  DISCONNECTED / CONNECTING / READY / FAILED / DISABLED

@dataclass
class McpServerStatus:
    server_id: str
    health: McpHealth
    tool_count: int
    generation: str | None
    last_error: str | None
    connected_at: datetime | None

class McpConnection:
    def __init__(self, config: McpServerConfig, resolver: McpSecretResolver, *,
                 client_info: Implementation, elicitation_callback: ... | None = None) -> None
    @property
    def status(self) -> McpServerStatus
    @property
    def catalog(self) -> McpToolCatalog | None
    def stderr_tail(self, limit: int = 200) -> list[str]
    async def connect(self) -> None
    async def disconnect(self) -> None
    async def refresh_catalog(self) -> McpToolCatalog
    async def call_tool(self, tool_name: str, arguments: dict[str, Any], *,
                        timeout_s: float | None = None) -> CallToolResult
    async def listen_for_changes(self, on_change: Callable[[str], None]) -> None

class McpConnectionManager:
    def __init__(self, store: McpConfigStore, resolver: McpSecretResolver,
                 consent: McpConsentGate) -> None
    async def start(self) -> None
    async def stop(self) -> None
    async def start_server(self, server_id: str) -> McpServerStatus
    async def stop_server(self, server_id: str) -> None
    async def restart_server(self, server_id: str) -> McpServerStatus
    async def test_connection(self, config: McpServerConfig) -> McpServerStatus
    def statuses(self) -> list[McpServerStatus]
    def connection(self, server_id: str) -> McpConnection | None
    def set_change_listener(self, listener: Callable[[str], None]) -> None
```

Requirements: reconnect with **bounded exponential backoff** and a cap; capture
child stderr into a bounded ring buffer that survives failure; `stop()` tears
down in deterministic order and leaves **zero** live child processes and zero
pending loop tasks. Use `terminate_windows_process_tree` / `close_process_job`
on Windows. Every coroutine runs on `ui/panels/async_bridge.ensure_loop()`.
`connect()` for a stdio server **must** consult the consent gate first and raise
`McpConsentDeniedError` without spawning anything when consent is refused.

#### `mcp/consent.py`

```python
class TrustState(enum.Enum):  UNTRUSTED / TRUSTED / DENIED
class ApprovalScope(enum.Enum):  ONCE / SESSION / ALWAYS

@dataclass(frozen=True, slots=True)
class DangerousPattern:
    token: str
    reason: str

def scan_command_for_dangerous_patterns(command: str, args: Sequence[str]) -> list[DangerousPattern]
def describe_launch(spec: StdioServerSpec, env: Mapping[str, str]) -> str

class TrustStore:
    def __init__(self, path: Path | None = None) -> None
    def state(self, server_id: str) -> TrustState
    def set_state(self, server_id: str, state: TrustState) -> None
    def generation(self, server_id: str) -> str | None
    def set_generation(self, server_id: str, generation: str) -> None
    def reset(self, server_id: str) -> None

class ApprovalStore:
    def __init__(self, path: Path | None = None) -> None
    def decision(self, namespace: str, function_name: str, generation: str) -> bool | None
    def remember(self, namespace: str, function_name: str, generation: str, *,
                 approved: bool, scope: ApprovalScope) -> None
    def invalidate_namespace(self, namespace: str) -> None

class McpConsentGate:
    def __init__(self, trust: TrustStore, prompt: Callable[[McpServerConfig, str, list[DangerousPattern]], bool]) -> None
    async def ensure_launch_consent(self, config: McpServerConfig, env: Mapping[str, str]) -> None
    def note_generation(self, server_id: str, generation: str) -> bool
```

`scan_command_for_dangerous_patterns` flags at minimum `sudo`, `rm -rf`,
`curl`/`wget` piped to a shell, `powershell -enc`, and paths under the user
home, `.ssh`, or system directories. `describe_launch` renders the command and
**every argument untruncated**, plus env var **names only** (never values), the
working directory, and the client-privilege warning. `note_generation` returns
`True` when the generation changed, and the caller then invalidates approvals.

#### `mcp/tool_source.py`

```python
UNTRUSTED_BLOCK_START: str
UNTRUSTED_BLOCK_END: str

def to_canonical_name(server_id: str, tool_name: str) -> str
def from_canonical_name(canonical: str) -> tuple[str, str]
def sanitize_untrusted_text(text: str, *, limit: int) -> str
def map_tool_to_function(entry: McpToolEntry) -> ToolFunction
def map_result(result: CallToolResult) -> tuple[list[ToolResultPart], bool]
def validate_structured_content(entry: McpToolEntry, content: Mapping[str, Any]) -> None

class McpToolSource:
    def __init__(self, manager: McpConnectionManager, registry: ToolRegistry) -> None
    def register_all(self) -> None
    def unregister_all(self) -> None
    def definitions(self) -> list[ToolDefinition]
    def entry_for(self, canonical_name: str) -> McpToolEntry | None
    def is_read_only(self, canonical_name: str) -> bool
    async def execute(self, function_name: str, arguments: dict[str, Any]) -> object
```

`map_tool_to_function` builds `ToolFunction(name=canonical, description=...,
parameters=[], returns=..., input_schema=entry.input_schema)` — the raw schema
passes through **verbatim**. `map_result` maps `CallToolResult.content` to the
`ToolResultPart` union and `structured_content` to `StructuredResultPart`,
returning `is_error` alongside. `register_all` registers one executor per
namespace via `registry.external_tools.register(...)` **and** pushes every
canonical name through `to_wire_name` to warm the reverse registry.
`is_read_only` implements design **C** (trust-gated annotations).
`validate_structured_content` resolves `$ref` against `output_schema` and raises
`McpProtocolError` on violation; a tool with no `output_schema` skips validation.

#### `mcp/policy.py`

```python
@dataclass(frozen=True, slots=True)
class ToolCost:
    canonical_name: str
    schema_tokens: int
    description_tokens: int

def estimate_tool_cost(function: ToolFunction) -> ToolCost
def enabled_entries(config: McpServerConfig, catalog: McpToolCatalog) -> tuple[McpToolEntry, ...]
```

#### `mcp/auth.py` (Phase 2)

```python
class KeyringTokenStorage(TokenStorage):
    def __init__(self, store: CredentialStore, server_id: str, issuer: str) -> None
    async def get_tokens(self) -> OAuthToken | None
    async def set_tokens(self, tokens: OAuthToken) -> None
    async def get_client_info(self) -> OAuthClientInformationFull | None
    async def set_client_info(self, info: OAuthClientInformationFull) -> None
    async def clear(self) -> None

async def resolve_client_identity(spec: HttpServerSpec, metadata_url: str | None) -> OAuthClientInformationFull
def build_oauth_provider(spec: HttpServerSpec, storage: KeyringTokenStorage, *,
                         redirect_handler: ..., callback_handler: ...) -> OAuthClientProvider
async def sign_out(store: CredentialStore, server_id: str) -> bool
```

Client-identity priority: CIMD via `create_client_info_from_metadata_url` when a
metadata URL is configured → pre-registered `oauth_client_id` → DCR last, logging
a deprecation warning. Enforce RFC 9207 with `credentials_match_issuer` and key
tokens per issuer so a token for server A can never be sent to server B. Reuse
`credentials/oauth.py`'s `OAuthCallbackServer` for the loopback redirect.

#### `mcp/resources.py` (Phase 2)

```python
async def list_resources(connection: McpConnection) -> list[ResourceSummary]
async def read_resource(connection: McpConnection, uri: str) -> list[ToolResultPart]
async def list_prompts(connection: McpConnection) -> list[PromptSummary]
async def get_prompt(connection: McpConnection, name: str, arguments: Mapping[str, str]) -> list[Message]
```

#### `mcp/sandbox_launch.py` (Phase 3, Windows)

```python
def build_sandboxed_startup(spec: StdioServerSpec, sandbox: McpSandboxSpec,
                            env: Mapping[str, str]) -> SandboxedLaunch
def apply_job_limits(handle: int, sandbox: McpSandboxSpec) -> None
```

Job object with active-process and memory caps, a restricted token, an explicit
env allowlist, `CREATE_NO_WINDOW`, and `cwd` confinement. Guard all Win32 use
behind `sys.platform == "win32"` with a real non-Windows fallback that refuses
sandboxed launch rather than silently running unsandboxed.

#### `mcp/apps.py` (Phase 3)

MCP Apps host surface, paired with `ui/panels/mcp_app_panel.py`.

### 6.2 Changes to existing files

**`core/tools.py`** — add the definition seam that mirrors the executor seam:

```python
ExternalDefinitionProvider = Callable[[], list[ToolDefinition]]

class ExternalToolRegistry:
    def register(self, namespace, executor, *, definitions: ExternalDefinitionProvider | None = None) -> None
    def definitions(self) -> list[ToolDefinition]
```

`ToolRegistry.get_tool_definitions()` appends `self._external_tools.definitions()`
**after** the bridge definitions. Keep the existing per-bridge exception
handling and apply the same isolation to each external provider so one failing
server cannot empty the catalog.

**`core/orchestrator.py`**

- `classify_tool_call`: before the `ToolName(...)` lookup, if the namespace
  starts with `NAMESPACE_PREFIX`, consult the injected MCP classifier and return
  `read_only` / `destructive`; unknown MCP namespace stays `destructive`.
- `Orchestrator.__init__` / a setter: accept an optional `McpToolSource` so the
  classifier and catalog are reachable. Do not import `intellicrack.mcp` at
  module scope in a way that creates a cycle — use `TYPE_CHECKING` plus a
  runtime setter.
- `_active_tool_definitions`: emit meta-tool → core tools → loaded bridge tools
  → **loaded MCP tools last** (design H).
- `_render_dynamic_tool_catalog`: add a "Connected MCP servers" section listing
  server id, tool count and health; wrap **all** server-supplied text in the
  untrusted block via `sanitize_untrusted_text`.
- `_handle_tools_search`: build the index over bridge **and** MCP definitions.
- `_maybe_handle_meta_tool`: the unloaded-tool guard must accept MCP canonical
  names.
- New `_message_tokens(message, tokenizer)` counting `content` **plus**
  serialized `tool_calls.arguments` and `tool_results` (including
  `content` parts); new `_tool_definitions_tokens(definitions, tokenizer)`.
  `trim_messages_to_context_window` gains `tool_overhead_tokens: int = 0` and
  computes `budget = int(context_window * 0.85) - tool_overhead_tokens`, raising
  `ToolError` when the budget is non-positive. `_trim_messages_for_provider`
  passes the live advertised-tool overhead.

**`core/session.py`**

```python
@dataclass
class McpServerState:
    server_id: str
    health: str
    tool_count: int
    generation: str | None
    last_error: str | None
```

Add `Session.mcp_servers: dict[str, McpServerState]` with serialization in
`save`/`load` and the JSON export/import pair. **Do not touch `tool_states` or
`loaded_tools`.** A session file written before this change must still load.

**`ui/confirmation_dialog.py`** — extend `_RememberKey` to
`(tool_name, function_name, generation)`; `remembered_decision` / `store_decision`
take an optional `generation: str | None = None`; add
`clear_decisions_for_source(namespace: str)`. Add the three approval-scope
controls (once / session / always) and surface the originating server.

**`ui/chat.py`** — tool-source attribution badge on each tool call/result, and
render multi-part MCP results (text, image, resource link) inline.

**`ui/app.py` / `ui/preferences.py`** — construct `McpConfigStore`,
`McpSecretResolver`, `McpConnectionManager`, `McpToolSource`; register into
`ToolRegistry.external_tools`; tear down on shutdown before
`shutdown_bridge_loop()`; add the settings entry point.

### 6.3 New UI files

- **`ui/mcp_config.py`** — `McpConfigDialog`, `McpServerEditor`,
  `McpServerListModel`, `McpToolToggleView`, `McpInputPromptDialog`.
  Add/edit/remove servers; stdio vs HTTP editors; JSON import; *Test connection*
  reporting the real discovered tool count; status and stderr log view;
  per-server and per-tool toggles showing token cost; auth entry; OAuth sign-in
  and sign-out (Phase 2).
  **Every background call must use `run_bridge_coroutine_async` and must not
  destroy a running worker on close** — use `worker_is_running` / `discard_worker`
  from `async_bridge`. A known live defect (PR #409 follow-up) is exactly this
  bug in Provider Settings; do not reproduce it.
- **`ui/mcp_consent_dialog.py`** — `McpServerConsentDialog` rendering
  `describe_launch` output in a read-only monospace view with no truncation and
  no eliding, dangerous patterns highlighted, Approve / Cancel, and a "trust this
  server" checkbox.
- **`ui/mcp_elicitation_dialog.py`** (Phase 2) — `McpElicitationDialog` building
  a form from `requestedSchema` (string/number/boolean/enum), plus URL mode.
- **`ui/panels/mcp_app_panel.py`** (Phase 3).

---

## 7. Phased work and acceptance contracts

Commit per item. Each contract is a statement the local session will gate.

**Phase 1**

1. `mcp/errors.py`, `mcp/config.py`, `mcp/secrets.py` — config round-trips
   field-identically; both root keys import to equal configs; bad `serverId`
   rejected; literal secret rejected; `${input:id}` resolves from keyring; no
   secret ever written to `mcp.json`.
2. `mcp/transport.py`, `mcp/connection.py` — stdio connect lists tools; child
   death → `FAILED` then bounded-backoff reconnect; `stop()` leaves zero
   descendants; stderr readable after failure; HTTP server rejects without the
   required header and succeeds with it; shell metacharacters refused.
3. `core/tools.py` definition seam + the four narrow items in §2.4 — external
   definitions reach `get_tool_definitions()`; one failing provider does not
   empty the catalog; bridges unchanged; old session files still load.
4. `mcp/catalog.py`, `mcp/tool_source.py` — `$ref`/`$defs`/`anyOf` schema
   reaches the provider boundary byte-identical; text+image+embedded result
   yields three ordered parts; `is_error` becomes a failed `ToolResult`;
   `get__weather` and a 90-char name round-trip through `to_wire_name`;
   300-tool server paginates; re-list inside `ttlMs` makes no second call.
5. `mcp/policy.py` + orchestrator discovery — `tools.search` finds an MCP tool
   and persists it to `loaded_tools`; disabled server/tool contributes nothing;
   `tools.search` survives a cap smaller than the MCP tool count; full MCP list
   never rendered in the prompt.
6. Context budget — history whose tool *results* alone exceed the window is
   trimmed; advertising a large MCP set measurably reduces the message budget;
   non-positive budget raises.
7. `mcp/consent.py` + consent dialog + classification — nothing spawns before
   consent; argv shown untruncated (test uses a 500-char argument); dangerous
   patterns flagged; untrusted server's `read_only_hint` ignored; `always`
   survives restart, `session` does not; tool-list change forces re-prompt.
8. `ui/mcp_config.py` + chat attribution — *Test connection* reports the real
   count; per-tool toggle changes the advertised set next turn; stderr visible;
   source badge shown; dialog does not destroy a running worker on close.

**Phase 2** — `mcp/auth.py` (CIMD → pre-registered → DCR; RFC 9728 discovery;
RFC 9207 rejection; per-issuer tokens) · MRTR elicitation (form + URL,
`requestState` echoed, cancel declines, round cap) · `listen_for_changes` wired
to generation bump and approval invalidation · `mcp/resources.py` + chat
attachments · `validate_structured_content` · sign-in/out UI.

**Phase 3** — `mcp/sandbox_launch.py` (restricted token, env allowlist, job
teardown, no console window) · `mcp/apps.py` + panel · **tasks extension: do not
start**, the SDK lacks it.

---

## 8. Risk mitigations that shape the code

- Resolve argv **without a shell**; reject shell metacharacters; never pass
  unresolved `${input:...}` to a child process.
- Bound everything a hostile server controls: per-server tool cap, truncated
  descriptions at the catalog boundary, a result size cap, and a per-call
  timeout. All server text goes through `sanitize_untrusted_text`.
- Keyring unavailable ⇒ the server **fails to start with a named error**, never
  starts unauthenticated.
- Do not import Qt from anything under `src/intellicrack/mcp/` — that package
  must stay GUI-free and importable headless.
- Never write MCP ids into `Session.tool_states`.

---

## 9. Non-goals — do not build these

Registry browsing or a server marketplace · MCP servers exposing Intellicrack's
own bridges · reimplementing the protocol (the SDK is the protocol layer) ·
HTTP+SSE and deprecated server-initiated paths beyond what `mode="auto"`
negotiates · any change to the provider/wire layer merged in `c977291b`
(`bridges/json_schema.py`, `providers/dialects/*`, `providers/tool_names.py`) ·
client-side DPoP or jwt-bearer · macOS/Linux sandboxing.

---

## 10. Explicitly out of scope for you — the local session owns these

Do not attempt any of the following, and do not write code whose only purpose is
to satisfy them:

- **Writing tests of any kind.** No new test files, no edits to existing tests.
- **Test infrastructure**, including the in-repo MCP test servers and any
  extension of `tests/_helpers/`.
- **Running or reporting any gate** other than `ruff`.
- **Spikes**: CIMD reachability for a desktop client, whether
  `create_windows_process` sets `CREATE_NO_WINDOW`, and mid-session tool-list
  reconciliation.
- GUI verification, Windows keyring verification, process-tree verification.

If you believe something needs a test to be trustworthy, note it in your final
summary instead of writing one.

---

## 11. Delivery

- Work on `feat/mcp-client`. Commit per item in §7 — items 3 and 8 touch the
  most existing files, so split those by subsystem into reviewable commits.
- Every file you touch ends `ruff check` clean.
- Open a pull request when done. In the PR description, list:
  1. Which phases and items are complete, and which are not.
  2. Every acceptance contract in §7 you believe your code satisfies but that
     has **not** been verified, so the local session knows what to gate.
  3. Anything left working-as-before because completing it properly needed an
     environment you did not have.
- Do not claim any test passed. Do not claim basedpyright is clean.
