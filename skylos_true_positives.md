# Skylos True Positives & Implementation Plan

> [!IMPORTANT]
> **Instructions for the Agent:**
> Implement all needed fixes, integrations, and wiring for the 27 true positive dead-code items listed below. Make every implementation fully functional, robust, and production release-ready.
> Ensure all changes adhere strictly to the rules in `AGENTS.md` and `GEMINI.md`:
>
> 1. **No placeholders or stubs**: Every implementation must be genuine, working, and fully realized.
> 2. **Type compliance**: Ensure all code is strictly type-annotated and fully `basedpyright` compliant with zero errors.
> 3. **Linting and docs**: All changes must pass `ruff check` and comply fully with `darglint` (Google-style docstrings).
> 4. **No comments or emojis**: Avoid unnecessary comments, TODOs, and emojis in both code and commit messages/pr-descriptions.

---

## 1. Bridges & Core Helpers

### `safe_call`

* **Location**: `src\intellicrack\bridges\_parse_helpers.py:115`
* **Plan**:
  * Replace legacy ad-hoc `try/except` blocks (such as those swallowing standard exceptions like `OSError` or `struct.error` from Win32 calls or binary parsing) across `src\intellicrack\bridges` with this unified helper.
  * Ensure absorbed errors are consistently logged at a debug level under the `"safe_call_failed"` event key for clear traceability.

### `pefile_available`

* **Location**: `src\intellicrack\bridges\installer.py:2204`
* **Plan**:
  * Integrate this helper into the main tool installer interface and diagnostic system to audit optional dependencies prior to executing PE-specific installs (like x64dbg or structural binary patches).
  * Gracefully disable actions or display clean warning dialogues when `pefile` is unavailable.

### `NamedPipeClient.format_error_hint`

* **Location**: `src\intellicrack\bridges\named_pipe_client.py:633`
* **Plan**:
  * Connect this method to the VNC widget's connection handling, sandbox management panels, and model orchestrators when interacting with background processes.
  * Use the mapped user-friendly error hints instead of reporting raw Win32 system codes.

### `dataclass_to_dict`

* **Location**: `src\intellicrack\bridges\sandbox_bridge.py:133`
* **Plan**:
  * Use this function to serialize sandbox instance metadata and states into JSON-safe dictionaries for API boundaries.
  * Replace redundant manual dictionaries building in `sandbox_bridge.py` with this standardized, safe mapping utility.

---

## 2. Core & Parsing Engines

### `get_disassembler`

* **Location**: `src\intellicrack\core\disassembler.py:417`
* **Plan**:
  * Replace individual instantiate calls of `HexDisassembler` with this singleton getter to maintain a unified disassembler engine instance throughout the UI panels, scripting engines, and LLM context formatters.

### `HexPatParser._peek`

* **Location**: `src\intellicrack\core\hexpat\parser.py:306`
* **Plan**:
  * Integrate into structural parsing loops in `parser.py` that require multiple steps of token lookahead to resolve recursive declarations, nested structs, or conditional type extensions.

### `BuiltinFunctions._read_struct_field`

* **Location**: `src\intellicrack\core\hexpat\stdlib.py:2781`
* **Plan**:
  * Register this method inside `register_all()` to expose it to the hexpat standard library (e.g., as `std::mem::read_struct_field`).
  * Enable parsing layouts to dynamically decode specific integer sizes directly from raw data offsets.

### `BuiltinTypes.all_names`

* **Location**: `src\intellicrack\core\hexpat\type_system.py:82`
* **Plan**:
  * Use this helper in compilation errors, lexer validators, and autocomplete panels to verify or suggest primitive type names.

---

## 3. Operations & Scripting

### `log_binary_operation`

* **Location**: `src\intellicrack\core\logging.py:604`
* **Plan**:
  * Wire this standard logger call into the file loading, patching, saving, and exporting pipelines inside the hex editor and disassembler panels to produce auditable operation logs.

### `Orchestrator._estimate_tokens`

* **Location**: `src\intellicrack\core\orchestrator.py:1405`
* **Plan**:
  * Keep this function active as a backward-compatibility proxy that forwards to the public `estimate_tokens` system to prevent legacy model plugins from crashing.

### `ProcessManager._terminate_process_sync`

* **Location**: `src\intellicrack\core\process_manager.py:521`
* **Plan**:
  * Use this method as a fallback synchronous terminator in `ProcessManager`'s cleanup sequence when psutil-based asynchronous tree-killing times out, preventing dangling processes during sudden app closures.

### `TransformPipeline.clear`

* **Location**: `src\intellicrack\core\transform_pipeline.py:845`
* **Plan**:
  * Bind this clear call to the "Reset Pipeline" or "Clear All Transforms" button in the hex editor's transform sidebar, resetting the bytes visualization to the original state.

### `YaraScanner.scan_data_async` & `YaraScanner.scan_file_async`

* **Location**: `src\intellicrack\core\yara_scanner.py:223` & `238`
* **Plan**:
  * Expose these background scanning routines to the signatures panel, providing users with fast, non-blocking Yara signature scanning alongside standard database checks.

---

## 4. Initialization & main

### `init_model_discovery` / `init_script_engine` / `init_template_manager`

* **Location**: `src\intellicrack\main.py:769`, `788`, `805`
* **Plan**:
  * Standardize the core startup flow of `main.py` by calling these public wrappers directly instead of bypassing them via their private equivalents (`_init_*`).
  * Ensure external extensions or CLI systems utilize these public endpoints when bootstrapping subsystems.

---

## 5. Hardware & Performance (GPU BAR Detection)

### `_load_cfgmgr`, `_locate_devnode`, `_read_descriptor_bytes`, `_parse_mem_descriptor`, `_enumerate_bars_for_log_conf`, `enumerate_pci_memory_bars`, `max_memory_bar_bytes`

* **Location**: `src\intellicrack\providers\gpu_pci_resources.py`
* **Plan**:
  * Integrate this resizable-bar auditing module into the local AI model discovery and provider config screens.
  * Use `max_memory_bar_bytes` to query windows PCI BAR size and warn users if a local LLM context profile exceeds actual GPU allocation sizes (preventing CPU-fallback slowdowns).

---

## 6. Sandboxes & VM Controls

### `QMPClient.stop`

* **Location**: `src\intellicrack\sandbox\qemu.py:538`
* **Plan**:
  * Bind this QMP pause action to the "Pause VM" controls on the sandbox panel, letting analysts freeze background sandboxes dynamically for live memory inspection.

---

## 7. UI Compatibility

### `edit_table_item`, `wheel_angle_delta_y`, `key_event_key`, `qt_key_page_up`, `qt_key_page_down`

* **Location**: `src\intellicrack\ui\panels\qt_compat.py`
* **Plan**:
  * Route mouse wheel events, key shortcuts, and page navigation across stack views, VNC panels, and table widgets through these wrappers to guarantee consistent PyQt6 input behaviors across platforms.
