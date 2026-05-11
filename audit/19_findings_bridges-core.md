> # Workgroup Directive — Execution Order 19/23: `bridges-core`
>
> Spawn a multi-agent workgroup to drive **every F-#### finding below** to
> production release-ready. The workgroup must run this pipeline for every
> finding in this file:
>
> 1. **`developer`** agents (in parallel where findings touch disjoint
>    files) — implement the full fix per the finding's `Suggested
>    remediation summary`. No placeholders, mocks, stubs, hardcoded
>    returns, or fake-success paths. Re-verify each finding against the
>    cited source/lines before fixing; if already resolved, annotate
>    `[obsolete]` with the resolving commit hash and move on.
> 2. **`code-reviewer`** — verify each fix actually addresses the failure
>    mode described in `Why this is non-functional` and audit every caller
>    listed under `Callers / blast radius` for regressions.
> 3. **`test-writer`** — author production-grade tests that fail without
>    the fix and pass with it. Tests must execute against real binaries,
>    real bridges, and real protocols. No mocks of the unit under test.
> 4. **`test-reviewer`** — confirm tests genuinely validate the fix and
>    meet Intellicrack's no-mock standard.
> 5. **`linter`** — run `ruff check`, `basedpyright`, `pydoclint`, and
>    `pydocstyle`; resolve every finding without suppression directives.
>
> Hard constraints (non-negotiable):
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - When this file is fully processed, every F-#### below must be either
>   fixed-and-tested or annotated `[obsolete]` with the resolving commit.
> - **All work for this file ships as one single PR (one PR per prompt /
>   per file).** Every F-#### in this file must be batched into the same
>   PR — do not split findings across multiple PRs, and do not merge any
>   subset until the whole file is fixed-and-tested or annotated
>   `[obsolete]`.
>
> ---
>
# Findings: bridges-core

## Files audited (5)

- src/intellicrack/bridges/**init**.py
- src/intellicrack/bridges/base.py
- src/intellicrack/bridges/_pe_format.py
- src/intellicrack/bridges/_win32_types.py
- src/intellicrack/bridges/schemas.py

## Findings

### Category 4 - Ineffective / Naive Implementations

#### F-0001 - normalize_type silently downgrades all unknown types to "string"

- **File:** `src/intellicrack/bridges/schemas.py`
- **Lines:** 181-197
- **Pattern:** Cat 4, "silently masks errors / loses information"
- **Excerpt:**

  ```python
  def normalize_type(param_type: str) -> str:
      """Normalize a parameter type to JSON Schema type.
      ...
      """
      param_type_lower = param_type.lower().strip()
      if param_type_lower in PYTHON_TO_JSON_TYPES:
          return PYTHON_TO_JSON_TYPES[param_type_lower]
      if param_type_lower in VALID_JSON_SCHEMA_TYPES:
          return param_type_lower
      return "string"
  ```

- **Why this is non-functional:** Any unrecognised type string (`"list[int]"`, `"Foo"`, `"bytes"`, `"Optional[int]"`, `"int|None"`) is silently coerced to `"string"`. Tool parameters that should be integers, lists, or objects will be advertised to every LLM provider as plain strings, causing the model to emit string arguments which then fail to coerce when the bridge function tries to use them as ints/lists. There is no log warning at the conversion point; the only safety net (`validate_tool_parameter`) is itself defeated by this fallback (see F-0002).
- **Callers / blast radius:** `src/intellicrack/bridges/schemas.py:214` (`build_schema_property`), `src/intellicrack/bridges/schemas.py:274` (`_build_google_schema_parameters`), `src/intellicrack/bridges/schemas.py:347` (`validate_tool_parameter`). Schemas built here flow into `to_anthropic_schema` / `to_openai_schema` / `to_google_schema` and ultimately `get_schema_for_provider` consumed by `core/orchestrator.py:1260` `_validate_tool_schemas`.
- **Suggested remediation summary:** Either raise / log a warning for unknown types and propagate it, or return a `(type, was_fallback)` tuple so the validator can flag it.

### Category 5 - Error Handling Anti-Patterns

#### F-0002 - validate_tool_parameter type check is permanently dead because normalize_type cannot return an invalid value

- **File:** `src/intellicrack/bridges/schemas.py`
- **Lines:** 347-355
- **Pattern:** Cat 5, "validation that cannot fire"; cross-reference Cat 20 (dead code)
- **Excerpt:**

  ```python
      normalized_type = normalize_type(param.type)
      if normalized_type not in VALID_JSON_SCHEMA_TYPES:
          errors.append(
              ValidationError(
                  f"Invalid type '{param.type}' (normalized to '{normalized_type}')",
                  location,
                  "warning",
              ),
          )
  ```

- **Why this is non-functional:** `normalize_type` (lines 181-197) is *guaranteed* to return one of the seven members of `VALID_JSON_SCHEMA_TYPES` (it falls back to `"string"` for unknown input). Therefore the `if normalized_type not in VALID_JSON_SCHEMA_TYPES` branch can never be true, the `errors.append(...)` body is unreachable, and no caller will ever see a "warning" diagnostic for a malformed type string. The validator pretends to detect bad type names but in fact accepts everything.
- **Callers / blast radius:** Called from `validate_tool_function` at `src/intellicrack/bridges/schemas.py:440`, which is called from `validate_tool_definition` at `src/intellicrack/bridges/schemas.py:483`, surfaced through `validate_and_convert` (`src/intellicrack/bridges/schemas.py:661`) used by `core/orchestrator.py:1260` `_validate_tool_schemas`. Production warning logging is suppressed because this branch never runs.
- **Suggested remediation summary:** Validate `param.type` *before* normalisation (compare against `PYTHON_TO_JSON_TYPES` keys plus `VALID_JSON_SCHEMA_TYPES`) so the warning fires when the developer wrote an unsupported type string.

### Category 13 - Logging / Observability Theater

#### F-0003 - validate_and_convert / get_schema_for_provider results are computed only to log a count

- **File:** `src/intellicrack/bridges/schemas.py`
- **Lines:** 645-679
- **Pattern:** Cat 13, "work performed solely to feed a log line"
- **Excerpt:**

  ```python
  def validate_and_convert(
      tool: ToolDefinition,
      provider: ProviderName,
  ) -> tuple[list[dict[str, Any]], list[ValidationError]]:
      ...
      schemas = get_schema_for_provider(tool, provider)
      _logger.debug(
          "schema_converted",
          tool=str(tool.tool_name),
          provider=str(provider),
          schema_count=len(schemas),
      )
      return schemas, errors
  ```

- **Why this is non-functional:** Together with `core/orchestrator.py:1260` (`_schemas, errors = validate_and_convert(tool, provider_name)`) and `core/orchestrator.py:1279` (`all_schemas = get_all_schemas_for_provider(tools, provider_name)`), the converted provider schemas are never sent to the LLM - the orchestrator passes raw `tool_definitions` to `_call_llm` and lets each provider re-convert. The full schema-build pipeline is therefore executed twice per agent loop iteration purely so the orchestrator can log `schema_count=...`. If `get_schema_for_provider` ever drifts from what the providers actually emit, no behavior changes; the log just becomes a lie.
- **Callers / blast radius:** `core/orchestrator.py:1260` (discards `_schemas`), `core/orchestrator.py:1279` (uses `all_schemas` only for `len()`). No production caller consumes the converted schema list returned from these functions.
- **Suggested remediation summary:** Either route the converted schemas to the provider call (so providers stop re-converting) or replace the conversion calls with a pure-validation pass that does not allocate the dict trees.

### Category 20 - Dead Code & Unreachable Paths

#### F-0004 - bridges/**init**.py public re-exports are unused by production code

- **File:** `src/intellicrack/bridges/__init__.py`
- **Lines:** 13-58
- **Pattern:** Cat 20, "exported symbol with no production importers"
- **Excerpt:**

  ```python
  from intellicrack.bridges.base import (
      BinaryOperationsBridge,
      BridgeCapabilities,
      ...
  )
  from intellicrack.bridges.cutter import CutterBridge
  from intellicrack.bridges.frida_bridge import FridaBridge
  from intellicrack.bridges.ghidra import GhidraBridge
  ...
  __all__: list[str] = [
      "BinaryOperationsBridge",
      ...
  ```

- **Why this is non-functional:** Every production importer of any bridge symbol uses the fully-qualified submodule path (`from intellicrack.bridges.base import ToolBridgeBase`, `from intellicrack.bridges.ghidra import GhidraBridge`, etc.). A repo-wide search for `from intellicrack\.bridges import \w+` returns only `tests/test_bridges/test_win32_types.py:15`. The package-level re-export block at the top of `__init__.py` therefore has no production consumers and forces every heavy bridge module (Frida 242 KB, Ghidra 259 KB, hex_editor 284 KB, x64dbg 227 KB, process 187 KB) to be eagerly imported the first time anything touches `intellicrack.bridges`, even when the caller only needed `intellicrack.bridges.base`.
- **Callers / blast radius:** No production callers. Only `tests/test_bridges/test_win32_types.py:15` relies on the package-level surface. Eager imports trigger the heavy bridges (frida_bridge, ghidra, x64dbg, hex_editor, process) the moment any code does `import intellicrack.bridges.<anything>`.
- **Suggested remediation summary:** Convert to lazy `__getattr__` re-exports or delete the `__all__` surface and rely on submodule imports.

### Category 21 - Documentation / Signature Drift

#### F-0005 - protection_to_string promised "rwx" / "r--" return shape is contradicted by its implementation

- **File:** `src/intellicrack/bridges/_win32_types.py`
- **Lines:** 949-972
- **Pattern:** Cat 21, "docstring lies about return shape / contract"
- **Excerpt:**

  ```python
  def protection_to_string(prot: int) -> str:
      """Convert a Win32 memory protection constant to a human-readable string.
      ...
      Returns:
          str: Protection string like 'rwx', 'r--', etc.
      """
      prot_map: dict[int, str] = {
          PAGE_NOACCESS: "---",
          PAGE_READONLY: "r--",
          PAGE_READWRITE: "rw-",
          PAGE_WRITECOPY: "rw-c",
          ...
          PAGE_EXECUTE_WRITECOPY: "rwxc",
      }
      base_prot = prot & 0xFF
      result = prot_map.get(base_prot, "???")
      if prot & PAGE_GUARD:
          result += "+G"
      return result
  ```

- **Why this is non-functional:** The docstring says the function returns a fixed-length protection triplet "like 'rwx', 'r--'", but the actual returned strings are 3 characters for the simple cases, 4 characters for the WRITECOPY variants ("rw-c", "rwxc"), three question marks ("???") for the unknown case, and an additional "+G" suffix when the guard bit is set. Callers that try to parse the result by character index (e.g. `result[0] == 'r'`) will break on WRITECOPY pages and on guard-protected pages.
- **Callers / blast radius:** Imported by `src/intellicrack/bridges/process.py` (line 127) and used inside ProcessBridge memory region enumeration. Any GUI or LLM consumer that treats the field as a fixed-shape `rwx` triplet will misclassify writecopy / guard pages.
- **Suggested remediation summary:** Either tighten the docstring to enumerate every possible suffix, or redesign the return as a typed dict with separate `read`, `write`, `execute`, `copy_on_write`, `guard` flags.

#### F-0006 - state_to_string and mem_type_to_string silently bucket all unknown values to "unknown"

- **File:** `src/intellicrack/bridges/_win32_types.py`
- **Lines:** 975-1006
- **Pattern:** Cat 21, "doc/contract drift"; cross-reference Cat 4 (naive)
- **Excerpt:**

  ```python
  def state_to_string(state: int) -> str:
      ...
      state_map: dict[int, str] = {
          MEM_COMMIT: "committed",
          MEM_RESERVE: "reserved",
          MEM_FREE: "free",
      }
      return state_map.get(state, "unknown")


  def mem_type_to_string(mem_type: int) -> str:
      ...
      type_map: dict[int, str] = {
          MEM_PRIVATE: "private",
          MEM_MAPPED: "mapped",
          MEM_IMAGE: "image",
      }
      return type_map.get(mem_type, "unknown")
  ```

- **Why this is non-functional:** The docstrings advertise the return as one of the listed states / types, but every other Win32 `MEM_*` value (MEM_DECOMMIT 0x4000, composite states) collapses to the literal `"unknown"`. There is no log line and no exception, so a downstream caller that records a process memory map will silently lose the distinction between "we never enumerated this kind of region before" and "we misread the field". The `"unknown"` bucket also collides with the `"???"` produced by `protection_to_string`, so the human reader cannot tell whether the failure is on the protection or the state side.
- **Callers / blast radius:** Both helpers are imported and called by `src/intellicrack/bridges/process.py` for memory region enumeration. Returned strings flow into ProcessBridge `get_memory_regions` and then into LLM context.
- **Suggested remediation summary:** Log unknown values at debug level with the raw int, return `f"unknown(0x{state:x})"`, and document the contract honestly.

### Category 24 - Recovery / Robustness Theater

#### F-0007 - ToolBridgeBase.shutdown does no real cleanup

- **File:** `src/intellicrack/bridges/base.py`
- **Lines:** 409-412
- **Pattern:** Cat 24, "cleanup helper that does not clean anything up"
- **Excerpt:**

  ```python
      async def shutdown(self) -> None:
          """Shutdown the tool and cleanup resources."""
          self._logger.info("bridge_shutdown", bridge_class=self.__class__.__name__)
          self._state = BridgeState()
  ```

- **Why this is non-functional:** The base implementation is non-abstract (so subclasses are not forced to override it) and only resets the in-memory `BridgeState` dataclass. The docstring says "cleanup resources" but there is no handle close, no subprocess kill, no socket teardown, no tempfile unlink. Every shipped subclass (`cutter.py:894`, `x64dbg.py:1860`, `process.py:915`, `frida_bridge.py:1291`, `ghidra.py:1183`, `hex_editor.py:1575`) calls `await super().shutdown()` first, but a future bridge author who relies on the default contract will leak file descriptors / child processes and the type system will not catch it. Compare with `initialize` and `is_available`, which *are* abstract for exactly this reason.
- **Callers / blast radius:** `src/intellicrack/main.py:914` (`orchestrator.shutdown()`) which fans out via `core/orchestrator.py:1827` (`await self._tools.shutdown()`) and `core/tools.py:199` (`await bridge.shutdown()`); `src/intellicrack/ui/panels/cutter_panel.py:174` and `src/intellicrack/ui/panels/ghidra_panel.py:206` / `:1303` invoke per-bridge shutdown directly. If anyone adds a new bridge that inherits ToolBridgeBase without overriding `shutdown`, those call sites will silently leak the bridge's resources.
- **Suggested remediation summary:** Either mark `shutdown` `@abstractmethod` (forcing every bridge to write its real cleanup) or have the base log a warning when used without override.
