> # Audit List 5/6
>
> Drive **every F-#### finding below** to production release-ready. For
> each finding: re-verify against the cited source/lines, implement the
> full fix per the `Suggested remediation summary`, and write
> production-grade tests that fail without the fix and pass with it. If a
> finding is already resolved on `main`, annotate it in this file by
> appending `[obsolete: <commit-hash>]` to the F-#### heading line (e.g.
> `#### F-0042 [obsolete: c0bfbdf9] - <original title>`) and move on.
>
> ## Orchestrator Responsibility (Claude)
>
> **Claude bears final, non-delegable responsibility for verifying that
> every fix is a real, root-cause solution — never a workaround,
> monkeypatch, or band-aid that masks the underlying defect.** Reject any
> change that:
>
> - Suppresses, hides, or routes around the failure mode instead of fixing
>   the cause described in `Why this is non-functional`.
> - Adds opt-in flags or "preserve old behavior" toggles that leave the
>   broken code path reachable.
> - Catches and swallows the symptom (logging-only, fake `success: True`,
>   silent fallback, bare `except`) instead of correcting the logic.
> - Replaces one fake-success path with a different fake-success path.
> - Disables, weakens, skips, or `xfail`s tests / assertions to silence a
>   failure.
> - Adds shim layers, polyfills, or compatibility wrappers when the
>   upstream call site or data structure should be corrected directly.
> - Inserts `type: ignore`, `pyright: ignore`, `noqa`, or other
>   suppression directives instead of fixing the actual defect.
> - Hardcodes a value, sentinel, or "known-good" response in place of the
>   real computation.
> - Monkeypatches at runtime or vendors a private copy of upstream code to
>   avoid touching the real broken site.
>
> Do not mark a finding resolved until the underlying defect is
> **actually** gone and the new tests would have caught the original bug.
>
> Hard constraints:
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - Every F-#### below must end fixed-and-tested or annotated
>   `[obsolete: <commit-hash>]` inline on its heading line in this file.
>
> ---

# Findings: bridges-cutter-frida

## Files audited (2)

- src/intellicrack/bridges/cutter.py
- src/intellicrack/bridges/frida_bridge.py

## Findings

### Category 16 - Binary Analysis-Specific Failures

#### F-0001 - save_binary uses `wtf {target}` which only writes the current block, not the whole binary

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 2148-2167
- **Pattern:** Cat 16, Cat 2
- **Why this is non-functional:** Rizin's `wtf` is `wtf <filename> [size] @ [addr]` and writes the current block (default 256 bytes), NOT the full binary with cached patches applied. To save the loaded binary with `io.cache=true` patches you need `wcf <file>`.

#### F-0002 - assemble_at writes the assembled bytes twice (`wa` then `wx`)

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1703-1719
- **Pattern:** Cat 4, Cat 16

### Category 5 - Error Handling Anti-Patterns

#### F-0003 - get_imports/get_exports/get_sections silently return [] when not analyzed

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1568-1596
- **Pattern:** Cat 5, Cat 2

#### F-0004 - get_resources swallows ToolError and returns empty list

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 2018-2034
- **Pattern:** Cat 5, Cat 24

### Category 22 - Test/Debug Code Leaked

#### F-0005 - hook_function leaks default `console.log('[+] Called ...')` instrumentation in production

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 1948-2042
- **Pattern:** Cat 22, Cat 13

### Category 8 - Type Safety Violations

#### F-0006 - Tool definition for `frida.scan_memory` declares pattern as "string" but Python signature requires bytes

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 288-306, 1681-1745
- **Pattern:** Cat 8, Cat 21, Cat 9

### Category 16 - Binary Analysis-Specific Failures (continued)

#### F-0007 - Frida `call_function` returns `result.toInt32()` for pointer return types, truncating 64-bit values

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2174-2245
- **Pattern:** Cat 16, Cat 19
- **Why this is non-functional:** For `return_type == "pointer"` on a 64-bit process, the result is a `NativePointer`. Calling `.toInt32()` truncates to a 32-bit signed integer.

### Category 19 - Data Parsing / Format Issues

#### F-0008 - read_memory `data` key collides between binary side-channel and JSON payload `data` field

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 1551-1585, 2280-2297, 1828-1881
- **Pattern:** Cat 19, Cat 16

### Category 6 - Resource & Lifecycle Issues

#### F-0009 - enable_crash_reporting registers an unbounded callback handler with no idempotency or off-switch

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 3587-3632
- **Pattern:** Cat 6, Cat 11

#### F-0010 - Detached scripts left in `_alloc_scripts`/`_stalker_scripts`/`_call_probes` when `_unload_script` raises silently

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2363-2376, 1253-1258
- **Pattern:** Cat 6, Cat 5, Cat 24

### Category 9 - Bridge / Tool Integration Failures

#### F-0011 - resolve_symbol returns a fabricated `sub_<addr>` name when DebugSymbol resolution fails

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2821-2867
- **Pattern:** Cat 2, Cat 16

#### F-0012 - `compile_typescript` instantiates `frida.Compiler()` once per call without disposal

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 6157-6248
- **Pattern:** Cat 6, Cat 7

### Category 7 - Concurrency / Async Issues

#### F-0013 - Stalker.unfollow issued from a separate script, not the script that owns Stalker.follow

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 3357-3478, 3450-3457
- **Pattern:** Cat 7, Cat 16

#### F-0014 - `_make_payload_waiter` and `_make_install_waiter` capture `loop = asyncio.get_running_loop()` at construction

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2318-2361, 2489-2536
- **Pattern:** Cat 7

### Category 14 - Security / Crypto Failures

#### F-0015 - JS template strings interpolate integer parameters without explicit `int()` validation

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** Multiple — 1569-1572, 1604-1608, 2231-2235, 2687-2690, 3945-3955, 5435-5438, 5503-5510 and many others
- **Pattern:** Cat 14, Cat 8

#### F-0016 - search_string_live and search_assembly_pattern use unescaped user input as r2 commands

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 2864-2883, 2885-2904
- **Pattern:** Cat 14, Cat 19

### Category 19 - Data Parsing / Format Issues (continued)

#### F-0017 - `_cmd_json` returns silent `[]` on JSON parse failure, masking command errors

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1733-1761
- **Pattern:** Cat 19, Cat 5

#### F-0018 - MemoryRegion always sets `state="MEM_COMMIT", type="MEM_PRIVATE"` (Windows-only constants) regardless of platform

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 1655-1679, 5391-5411
- **Pattern:** Cat 2, Cat 15, Cat 21

### Category 4 - Ineffective Implementations

#### F-0019 - get_function_address triggers full functions enumeration, then filters in Python

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1802-1813
- **Pattern:** Cat 4

#### F-0020 - search_strings requires `_analyzed` but the underlying `izj` doesn't need analysis

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1389-1437, 1815-1850
- **Pattern:** Cat 5, Cat 4

### Category 5 - Error Handling Anti-Patterns (continued)

#### F-0021 - `_execute_script_and_wait` returns a result dict that "looks successful" after a timeout

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2247-2316
- **Pattern:** Cat 5, Cat 2

#### F-0022 - allocate_memory loop doesn't break after extracting addr; later error message can unload script after addr capture

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2693-2728, 3995-4029
- **Pattern:** Cat 6, Cat 5

### Category 24 - Recovery / Robustness Theater

#### F-0023 - Generic `except Exception` blocks throughout swallow Frida transport errors with only str() context

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** Multiple
- **Pattern:** Cat 5, Cat 24

#### F-0024 - shutdown() calls super().shutdown() AFTER releasing all references

- **Files:** `src/intellicrack/bridges/frida_bridge.py:1209-1292`, `src/intellicrack/bridges/cutter.py:878-895`
- **Pattern:** Cat 24, Cat 6

### Category 20 - Dead Code

#### F-0025 - `r2.setter` never used; the bridge writes to `self._r2` directly everywhere

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 757-774
- **Pattern:** Cat 20

### Category 18 - GUI / UX Wiring

#### F-0026 - Cutter bridge declares `supports_dynamic_analysis=False` but exposes 5 ESIL emulation tools

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 741-755, 2422-2519
- **Pattern:** Cat 18, Cat 21

### Category 11 - Persistence / State Issues

#### F-0027 - `_alloc_scripts` mapping never garbage-collects entries when the script unloads via other paths

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 2669-2728, 3964-4029, 1253-1258
- **Pattern:** Cat 11, Cat 6

### Category 21 - Documentation / Signature Drift

#### F-0028 - `assemble_at` returns `bytes` but tool definition says "Assembled bytes"

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 382-390, 1680-1719
- **Pattern:** Cat 21, Cat 9

### Category 19 - Data Parsing

#### F-0029 - Cutter `is_64bit` heuristic compares `bits == 64` only

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 78-80, 990-1006, 1052-1065
- **Pattern:** Cat 16, Cat 19

### Category 5 - Error Handling

#### F-0030 - `attach()` calls `await self.initialize()` unconditionally; init errors masquerade as attach errors

- **File:** `src/intellicrack/bridges/frida_bridge.py`
- **Lines:** 1309-1351, 1352-1404, 1406-1490, 3083-3104, 4605-4630
- **Pattern:** Cat 5, Cat 6

### Category 2 - Hardcoded Returns

#### F-0031 - get_function returns hardcoded `0` for parameter and local variable size; fixed `location="stack"` for all params

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1145-1219, 1188-1206
- **Pattern:** Cat 2, Cat 16

### Category 4 - Ineffective Implementations

#### F-0032 - get_classes maps rizin `methods` and `fields` lists to ClassInfo as raw `list[Any]` without parsing

- **File:** `src/intellicrack/bridges/cutter.py`
- **Lines:** 1953-1977
- **Pattern:** Cat 4, Cat 19

# Findings: core-hexpat

## Files audited (15)

- src/intellicrack/core/hexpat/**init**.py
- src/intellicrack/core/hexpat/_pragma.py
- src/intellicrack/core/hexpat/ast_nodes.py
- src/intellicrack/core/hexpat/data_reader.py
- src/intellicrack/core/hexpat/errors.py
- src/intellicrack/core/hexpat/evaluator.py
- src/intellicrack/core/hexpat/interpreter.py
- src/intellicrack/core/hexpat/lexer.py
- src/intellicrack/core/hexpat/parser.py
- src/intellicrack/core/hexpat/pattern_registry.py
- src/intellicrack/core/hexpat/preprocessor.py
- src/intellicrack/core/hexpat/stdlib.py
- src/intellicrack/core/hexpat/tokens.py
- src/intellicrack/core/hexpat/type_system.py
- src/intellicrack/core/hexpat_compiler.py

## Findings

### Category 1 - Empty / Stub Implementations

#### F-0001 - `builtin_print` evaluator no-op silently swallows arguments

- **File:** `src/intellicrack/core/hexpat/evaluator.py`
- **Lines:** 2370-2371
- **Pattern:** Cat 1
- **Why this is non-functional:** Bare-name `print(...)` invocation surface is a one-line return discarding all arguments. Not the `std::print` registered by `BuiltinFunctions._io_print`. Any pattern calling plain `print(msg)` gets a silent no-op rather than logging.

### Category 2 - Hardcoded Constants

#### F-0002 - `_mem_base_address` hardwires 0 instead of honouring `pragma.base_address`

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 567-577
- **Pattern:** Cat 2
- **Why this is non-functional:** `std::mem::base_address` always returns `0` regardless of `#pragma base_address` or `offset` parameter. Patterns relying on it to compute absolute file offsets read wrong locations.

#### F-0003 - `_core_array_index` always returns 0; `set_array_index` never invoked

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 1863-1872
- **Pattern:** Cat 2
- **Why this is non-functional:** `std::core::array_index()` returns `_array_index`, only mutated by `set_array_index` which is never called. Evaluator maintains independent stack but never propagates to stdlib.

### Category 9 - Critical: Non-Functional Pattern Compilation

#### F-0004 - `builtin::*` namespace path is unreachable; std-lib delegations always fail

- **File:** `src/intellicrack/core/hexpat/evaluator.py`
- **Lines:** 1871-1893
- **Pattern:** Cat 9, Cat 4
- **Excerpt:**

  ```python
  def _eval_namespace_access(self, node: NamespaceAccessExpr) -> PatternValue:
      ...
      ns_name = ns_val.value if isinstance(ns_val.value, str) else ""
      builtin_name = f"{ns_name}::{node.member}"
      scope_val = self._scope.get(builtin_name)
      if scope_val is not None:
          return scope_val
      msg = f"namespace has no member '{node.member}'"
      raise HexPatRuntimeError(msg, node.line, node.column)
  ```

- **Why this is non-functional:** HexPat std-lib `.pat` files all delegate to `builtin::std::*::name(...)`. Parser turns this into chained `NamespaceAccessExpr`. Evaluation recurses to leftmost `IdentifierExpr("builtin")`, which `_eval_identifier` resolves through `self._builtins` (10 names) and `self._scope` — neither contains `"builtin"`, so the call raises `undefined variable 'builtin'` long before the flat-string fallback ever runs. **Over 100 `builtin::...` keys are dead code under the current namespace-access lookup.**

#### F-0005 - `HexPatInterpreter.compile_to_json` swallows runtime errors as `HexPatError`

- **File:** `src/intellicrack/core/hexpat/interpreter.py`
- **Lines:** 213-237
- **Pattern:** Cat 5

### Category 5 - Reflection / Hook Mechanism Dead

#### F-0006 - Reflection provider hooks raise on every call because no caller installs a provider

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 144-181, 260-267, 1898-2169
- **Pattern:** Cat 5, Cat 20
- **Why this is non-functional:** `BuiltinFunctions.set_reflection_provider` is the only entry point; never invoked. Every `std::core::has_attribute / get_attribute_argument / member_count / has_member / formatted_value / set_pattern_color / execute_function` raises `HexPatRuntimeError("... requires evaluator metadata not yet wired")`.

#### F-0007 - `set_print_sink` is dead code: never called from any consumer

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 73-87
- **Pattern:** Cat 20
- **Why this is non-functional:** GUI never registers a sink, so `_io_print` only emits a structured log entry and the user never sees print output in the hex-editor UI panel.

### Category 12 - Wrong-Default Bypassed-Setting

#### F-0008 - `std::core::set_endian` does not affect subsequent struct-field reads

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 1842-1850
- **Pattern:** Cat 12
- **Why this is non-functional:** `BuiltinFunctions._endian` is private state on stdlib instance, never reaches `HexPatEvaluator._default_endian` used by every primitive struct/field read.

#### F-0009 - `BuiltinFunctions._endian` ignores `pragma.endian`

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 191-208
- **Pattern:** Cat 12
- **Why this is non-functional:** Hardcoded `"little"` default. Even with `#pragma endian big`, `_mem_read_unsigned(off, sz, ENDIAN_NATIVE)` reads little-endian.

### Category 21 - Wrong/Mismatched Built-in Names

#### F-0010 - `std::string::parse_int` registered as `to_int`; std-lib calls fail

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 309-317, 662
- **Pattern:** Cat 21
- **Why this is non-functional:** `vendor/ImHex-Patterns/includes/std/string.pat:99` calls `builtin::std::string::parse_int`. Not registered.

#### F-0011 - Multiple `builtin::std::mem::*` callees referenced by std-lib but never registered

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 290-463
- **Pattern:** Cat 21
- **Why this is non-functional:** Missing names: `read_bits`, `find_string_in_range`, `create_section`, `delete_section`, `get_section_size`, `set_section_size`, `copy_to_section`, `copy_value_to_section`, `current_bit_offset`. Each referenced by `vendor/ImHex-Patterns/includes/std/mem.pat`.

### Category 19 - Silent Drop of Language Feature

#### F-0012 - Variadic function parameters parsed but ignored at call time

- **File:** `src/intellicrack/core/hexpat/evaluator.py`
- **Lines:** 1819-1850
- **Pattern:** Cat 19
- **Why this is non-functional:** `_call_user_function` iterates only over `decl.params` and binds at most one argument per declared parameter. Excess arguments to `fn foo(auto ... args)` silently dropped. Breaks every std-lib trampoline.

#### F-0013 - Generic templates parsed but completely ignored

- **File:** `src/intellicrack/core/hexpat/evaluator.py`
- **Pattern:** Cat 19
- **Why this is non-functional:** Parser collects `template_params` and `template_args`. Evaluator references neither. `Foo<u32>` and `Foo<u8>` get the same byte layout.

#### F-0014 - `using` alias rejects array, pointer, and padding targets

- **File:** `src/intellicrack/core/hexpat/evaluator.py`
- **Lines:** 480-498
- **Pattern:** Cat 19

### Category 19 - Type System Collision

#### F-0015 - Namespaced types collide on local name in the global type table

- **File:** `src/intellicrack/core/hexpat/type_system.py`
- **Lines:** 166-216, 218-226
- **Pattern:** Cat 19
- **Why this is non-functional:** `register_struct(decl)` uses unqualified `decl.name`. Two namespaces declaring same local type name overwrite each other.

### Category 13 - Misleading Logging

#### F-0016 - Legitimate `break`/`continue` are logged at WARNING level

- **File:** `src/intellicrack/core/hexpat/evaluator.py`
- **Lines:** 591-596, 618-622
- **Pattern:** Cat 13

### Category 4 - Duplicate Implementations

#### F-0017 - Two divergent `format` implementations with different syntax

- **Files:** `evaluator.py:2373-2386`, `stdlib.py:2241-2290`
- **Pattern:** Cat 4
- **Why this is non-functional:** Bare-name `format(...)` supports only `{}` placeholders; stdlib's `_io_format` supports `{}`, `{n}`, `{:spec}`. Calling `format("{:08X}", x)` produces `{:08X}` literally.

### Category 20 - Dead Code

#### F-0018 - Unreachable `_endian` fallback in `_core_set_endian`

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 1842-1850
- **Pattern:** Cat 20

### Category 19 - Validation Hole

#### F-0019 - `_eval_array_field` ignores `is_pointer` for pointer-array fields

- **File:** `src/intellicrack/core/hexpat/evaluator.py`
- **Lines:** 1313-1319
- **Pattern:** Cat 19

### Category 20 - Dead Code

#### F-0020 - `BuiltinFunctions.set_array_index` defined but never called

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 252-258
- **Pattern:** Cat 20

### Category 9 - Cross-Component Wiring Gap

#### F-0021 - `interpreter.execute()` never connects evaluator/state to stdlib

- **File:** `src/intellicrack/core/hexpat/interpreter.py`
- **Lines:** 100-186
- **Pattern:** Cat 9
- **Why this is non-functional:** Interpreter never calls `set_print_sink`, `set_reflection_provider`, `set_array_index`. Doesn't propagate `pragma.endian` into stdlib. Combined with F-0003/F-0006/F-0007/F-0009, ships with reflection/print/array-index/endian-config surface permanently disabled.

### Category 21 - Documentation Drift

#### F-0022 - `_resolve_endian` docstring promises pragma-aware native; implementation ignores pragma

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 269-282
- **Pattern:** Cat 21

### Category 24 - Recovery Theater

#### F-0023 - `parser.parse()` collects errors but never returns them

- **File:** `src/intellicrack/core/hexpat/parser.py`
- **Lines:** 158-195
- **Pattern:** Cat 24

### Category 21 - Spec/Behaviour Drift

#### F-0024 - `HexPatPreprocessor.process` discards `pragma.base_address` from emitted source

- **File:** `src/intellicrack/core/hexpat/preprocessor.py`
- **Lines:** 92-206
- **Pattern:** Cat 21

### Category 21 - String-Reflection Path Wrong

#### F-0025 - `_eval_namespace_access` synthesises `f"{ns_name}::{member}"` from short namespace name

- **File:** `src/intellicrack/core/hexpat/evaluator.py`
- **Lines:** 1883-1893
- **Pattern:** Cat 21
- **Why this is non-functional:** Multi-segment access like `std::mem::read_unsigned` becomes `"mem::read_unsigned"` not `"std::mem::read_unsigned"`. Fallback never finds flat builtin keys.

### Category 19 - Codegen Behaviour Drift

#### F-0026 - `HexPatCompiler.compile` accepts patterns the evaluator can run; static template silently drops semantics

- **File:** `src/intellicrack/core/hexpat_compiler.py`
- **Lines:** 487-565
- **Pattern:** Cat 19

### Category 1 - Imported Name Without Implementation

#### F-0027 - `_io_print` registers under bare `print` only via the unreachable namespace path

- **File:** `src/intellicrack/core/hexpat/stdlib.py`
- **Lines:** 453-459
- **Pattern:** Cat 1

### Category 12 - Configuration Threshold

#### F-0028 - `pragma.eval_depth` default of 32 trips on common `parent`/recursive patterns

- **File:** `src/intellicrack/core/hexpat/_pragma.py`
- **Lines:** 30-40
- **Pattern:** Cat 12

## Cross-cutting summary

The combination of F-0004 + F-0025 means the entire `builtin::std::*` namespace path is unreachable. Combined with F-0006/F-0007 (no reflection provider, no print sink) and F-0009 (hardcoded endian), the HexPat interpreter ships with vast portions of its advertised standard-library surface permanently disabled.

# Findings: ui-app-core

## Files audited (19)

- src/intellicrack/ui/**init**.py
- src/intellicrack/ui/_dialogs.py
- src/intellicrack/ui/_hex_format.py
- src/intellicrack/ui/_screen_compat.py
- src/intellicrack/ui/app.py
- src/intellicrack/ui/chat.py
- src/intellicrack/ui/confirmation_dialog.py
- src/intellicrack/ui/highlighter.py
- src/intellicrack/ui/panel_dock.py
- src/intellicrack/ui/preferences.py
- src/intellicrack/ui/provider_config.py
- src/intellicrack/ui/sandbox_config.py
- src/intellicrack/ui/session_manager.py
- src/intellicrack/ui/tool_config.py
- src/intellicrack/ui/tools.py
- src/intellicrack/ui/win32_embed.py
- src/intellicrack/ui/xpu_status.py
- src/intellicrack/ui/dialogs/**init**.py
- src/intellicrack/ui/dialogs/splash_screen.py

## Findings

### Category 18 - GUI / UX Wiring Defects

#### F-0001 [obsolete: 0de71369] - HxD toolbar button is permanently broken (target method does not exist)

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 743-747, 2095-2111
- **Pattern:** Cat 18
- **Why this is non-functional:** `add_hxd_tab` is never defined anywhere in the codebase. The toolbar exposes a prominent HxD button that, every single time the user clicks it, only calls `_show_tool_error("HxD", "HxD panel not available")`.

#### F-0002 - "Save Patched Binary..." menu item always reports "No hex editor loaded"

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1431-1446
- **Pattern:** Cat 18
- **Why this is non-functional:** `ToolOutputPanel.get_panel(panel_id)` returns from `self.panels`, but the hex editor is registered under `self.embedded_tools["hex_editor"]`, not `self.panels`.

#### F-0003 - Sandbox panel "active widget" lookup always returns None (wrong dict)

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 2283-2285
- **Pattern:** Cat 18

#### F-0004 - XPUStatusDialog is built and documented but never wired into any menu

- **File:** `src/intellicrack/ui/xpu_status.py`
- **Lines:** 83-105 (whole file, 401 lines)
- **Pattern:** Cat 18

#### F-0005 - FunctionListPanel and XRefPanel are wired but never populated with data

- **File:** `src/intellicrack/ui/tools.py`
- **Lines:** 845-851, 917-936
- **Pattern:** Cat 18

#### F-0006 - `_on_view_scripts` collects script panel state then discards it

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 548-556
- **Pattern:** Cat 13, Cat 18

#### F-0007 - "Tool Status..." menu prefetches statuses and pixmaps that are never passed to the dialog

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1482-1504
- **Pattern:** Cat 13, Cat 18

#### F-0008 - "Configure Tools..." dialog is created without the live tool registry

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1506-1514
- **Pattern:** Cat 18

#### F-0009 - `MainWindow._on_open_sandbox` constructs a throwaway SandboxConfigDialog just to call `is_sandbox_available()`

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1948-1956
- **Pattern:** Cat 11

#### F-0010 - `_apply_provider_settings` silently ignores providers that the user disables

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1602-1644
- **Pattern:** Cat 5

### Category 18 - Orphaned Signals (no slot connected)

#### F-0011 - `PreferencesDialog.settings_changed` signal has no consumers

- **File:** `src/intellicrack/ui/preferences.py`
- **Lines:** 461-464, 645-649

#### F-0012 - `SessionManagerDialog.session_loaded` and `session_deleted` signals have no consumers

- **File:** `src/intellicrack/ui/session_manager.py`
- **Lines:** 75-76, 515, 551

#### F-0013 - `ProviderConfigDialog.provider_updated` and `active_provider_changed` signals have no consumers

- **File:** `src/intellicrack/ui/provider_config.py`
- **Lines:** 962-963, 1277, 1345

#### F-0014 - `ModelSelectionDialog.model_selected` signal has no external consumers

- **File:** `src/intellicrack/ui/provider_config.py`
- **Lines:** 2647-2650, 2779

#### F-0015 - `SandboxConfigDialog.settings_updated` signal has no consumers

- **File:** `src/intellicrack/ui/sandbox_config.py`
- **Lines:** 280, 717

#### F-0016 - `SandboxMonitorWidget.sandbox_stopped` signal has no consumers

- **File:** `src/intellicrack/ui/sandbox_config.py`
- **Lines:** 886, 1016

#### F-0017 - `ToolConfigDialog.tool_updated` signal has no consumers

- **File:** `src/intellicrack/ui/tool_config.py`
- **Lines:** 745, 856

#### F-0018 - `ToolSettingsWidget.status_changed` signal has no consumers

- **File:** `src/intellicrack/ui/tool_config.py`
- **Lines:** 878, 1092

#### F-0019 - `ToolOutputPanel.embedded_tool_started` and `embedded_tool_closed` signals have no consumers

- **File:** `src/intellicrack/ui/tools.py`
- **Lines:** 775-776, 1098-1099

### Category 20 - Dead / Unreachable Code

#### F-0020 - `ToolConfirmationDialog.remember_similar` is captured but never read by callers

- **File:** `src/intellicrack/ui/confirmation_dialog.py`
- **Lines:** 73-80, 228-249
- **Pattern:** Cat 20

#### F-0021 - `ToolOutputPanel.wire_sandbox_backend` is a deprecated no-op never called

- **File:** `src/intellicrack/ui/tools.py`
- **Lines:** 2123-2133
- **Pattern:** Cat 20

### Category 4 - Ineffective / Naive Implementations

#### F-0022 - `ProviderSettingsWidget._setup_provider_specific_ui` only wires three of seven providers

- **File:** `src/intellicrack/ui/provider_config.py`
- **Lines:** 1670-1707
- **Pattern:** Cat 4

#### F-0023 - `MainWindow._on_browse_models_result` opens `ModelSelectionDialog` without provider context

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 1756-1786
- **Pattern:** Cat 4

### Category 6 - Hardcoded / Environment-Specific Values

#### F-0024 - Hardcoded `D:/Intellicrack/...` paths in tool and sandbox defaults

- **Files:** `src/intellicrack/ui/tool_config.py:762`, `src/intellicrack/ui/sandbox_config.py:536`
- **Pattern:** Cat 6

### Category 13 - Logging / Observability Theater

#### F-0025 - `MainWindow._on_provider_changed` only logs the change

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 2347-2356
- **Pattern:** Cat 13

### Category 5 - Error Handling Anti-Patterns

#### F-0026 - `MainWindow._refresh_system_status` silently swallows errors and never disables the timer

- **File:** `src/intellicrack/ui/app.py`
- **Lines:** 838-858
- **Pattern:** Cat 5
