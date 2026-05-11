> # Workgroup Directive — Execution Order 05/23: `core-hexpat`
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
