> # Workgroup Directive — Execution Order 11/23: `core-analysis`
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
# Findings: core-analysis

## Files audited (8)

- src/intellicrack/core/analysis_aggregator.py
- src/intellicrack/core/disassembler.py
- src/intellicrack/core/yara_scanner.py
- src/intellicrack/core/transform_pipeline.py
- src/intellicrack/core/script_gen.py
- src/intellicrack/core/template_manager.py
- src/intellicrack/core/_xml_gen.py
- src/intellicrack/core/_xml_gen.pyi

## Findings

### Category 1 - Empty / Stub Implementations

#### F-0001 - ScriptGenerator.**init** has empty body and class is a no-op shell

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 805-826
- **Pattern:** Cat 1
- **Excerpt:**

  ```python
  class ScriptGenerator:
      """Stable public entry point for building AI prompts that generate scripts.
      ...
      """

      def __init__(self) -> None:
          """Initialize the ScriptGenerator instance."""

      @staticmethod
      def prepare_ai_prompt(context: ScriptContext, language: ScriptLanguage) -> str:
  ```

- **Why this is non-functional:** Empty `__init__`, every public method is `@staticmethod` or could be, the class adds no behaviour over module-level functions. Stub class wrapped in fictional architectural narrative.
- **Callers / blast radius:** `src/intellicrack/main.py:659`, `src/intellicrack/ui/app.py`, `src/intellicrack/ui/tools.py`, `src/intellicrack/ui/panels/script_manager.py`, `src/intellicrack/core/orchestrator.py`.

### Category 2 - Hardcoded Return Values & Fake Success

#### F-0002 - Default fallback architecture silently coerces unrecognised binaries to x86-64

- **File:** `src/intellicrack/core/disassembler.py`
- **Lines:** 58-59, 316-320
- **Pattern:** Cat 2
- **Excerpt:**

  ```python
  _CAPSTONE_DEFAULT_ARCH_MODE: tuple[str, str] = ("x86", "64")
  ...
      result = _CAPSTONE_ARCH_MODE_MAP.get(arch)
      if result is None:
          _logger.debug("arch_detection_fallback", reason="unrecognised binary format")
          return _CAPSTONE_DEFAULT_ARCH_MODE
      return result
  ```

- **Why this is non-functional:** Unknown architectures get x86-64; downstream `disassemble()` produces structurally well-formed but semantically nonsense output - real instructions interpreted as x86. The log is `debug`-level so silent misclassification doesn't surface.

#### F-0003 - ScriptValidator.validate returns success for unknown languages without checking

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 487-511
- **Pattern:** Cat 2
- **Excerpt:**

  ```python
  if validator := validators.get(script.language):
      ...
  _logger.debug("script_validation_skipped", script=script.name, language=script.language.value)
  script.verified = True
  return True, None
  ```

- **Why this is non-functional:** R2_COMMANDS and X64DBG_SCRIPT have no validator; method sets `script.verified = True` regardless. The `verified` attribute means "we did not look".

### Category 4 - Ineffective / Naive Implementations

#### F-0004 - validate_java uses substring containment for "import" and "public"

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 462-485
- **Pattern:** Cat 4
- **Excerpt:**

  ```python
  if "import" not in content:
      ...
      return False, "Missing required element: import"

  if "public" not in content:
      ...
      return False, "Missing required element: public"
  ```

- **Why this is non-functional:** `"import"`/`"public"` substring matches succeed inside string literals/comments/identifiers. Brace counting rejects `String s = "}"` as unbalanced.

#### F-0005 - Aggregator deduplicates imports/exports by address only

- **File:** `src/intellicrack/core/analysis_aggregator.py`
- **Lines:** 203-236
- **Pattern:** Cat 4
- **Excerpt:**

  ```python
  def _deduplicate_imports(imports: list[ImportInfo]) -> list[ImportInfo]:
      seen: set[int] = set()
      result: list[ImportInfo] = []
      for imp in imports:
          if imp.address not in seen:
              seen.add(imp.address)
              result.append(imp)
      return result
  ```

- **Why this is non-functional:** Imports with `address == 0` (unbound, by-ordinal) all collapse to one. Forwarder exports on the same trampoline get coalesced. Natural key should be `(dll, function, ordinal)`.

### Category 11 - Persistence / State Issues

#### F-0006 - reload_script ignores subdir saves and silently fails

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 681-711
- **Pattern:** Cat 11
- **Excerpt:**

  ```python
  def reload_script(self, name: str) -> bool:
      ...
      ext = script.get_extension()
      filename = f"{name}{ext}"
      path = self.scripts_dir / filename
      if not path.exists():
          _logger.debug("script_reload_file_missing", script=name, path=str(path))
          return False
  ```

- **Why this is non-functional:** `save_script(name, subdir="...")` writes to `scripts_dir / subdir / filename`, but `reload_script` only ever looks at `scripts_dir / filename`. Any script saved with a subdir is unreloadable.

### Category 13 - Logging / Observability Theater

#### F-0007 - Script.save logs "script_file_written" before the file is actually written

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 333-343
- **Pattern:** Cat 13
- **Excerpt:**

  ```python
  def save(self, path: Path) -> None:
      path.parent.mkdir(parents=True, exist_ok=True)
      _logger.debug("directory_ensured", directory=str(path.parent))
      _logger.info("script_file_written", path=str(path), size=len(self.content))
      path.write_text(self.content, encoding="utf-8")
      _logger.info("script_saved", path=str(path), size=len(self.content))
  ```

- **Why this is non-functional:** Line 341 emits `script_file_written` BEFORE write. If write raises, observability sees "file written" event followed by no "script_saved" event - and no error event because no `except`.

#### F-0008 - TemplateManager logs "file_written" before write completes

- **File:** `src/intellicrack/core/template_manager.py`
- **Lines:** 230-245, 313-334
- **Pattern:** Cat 13

#### F-0009 - disassemble_to_lines logs constant `binary_path="<bytes-buffer>"`

- **File:** `src/intellicrack/core/disassembler.py`
- **Lines:** 279-289
- **Pattern:** Cat 13

#### F-0010 - validate_javascript logs `temp_file_unlink` and `temp_file_cleaned` around the same call

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 438-441
- **Pattern:** Cat 13

### Category 14 - Security / Crypto Failures

#### F-0011 - _xml_gen obfuscates xml.etree import to evade bandit B405

- **File:** `src/intellicrack/core/_xml_gen.py`
- **Lines:** 1-32
- **Pattern:** Cat 14
- **Excerpt:**

  ```python
  """XML generation utilities wrapper.
  ...
  Uses runtime string construction to avoid B405 bandit finding. ...
  """
  import importlib

  _et = importlib.import_module("xml.etree" + "." + "ElementTree")

  Element = _et.Element
  ```

- **Why this is non-functional:** Concatenating `"xml.etree" + "." + "ElementTree"` and feeding to `importlib.import_module` loads the same vulnerable module - just hides it from the linter. CLAUDE.md forbids this kind of suppression.

### Category 21 - Documentation / Signature Drift

#### F-0012 - script_gen module docstring promises script execution that does not exist

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 5-31
- **Pattern:** Cat 21
- **Why this is non-functional:** Closing bullet promises "Script management (save, load, execute)" but no `execute` method exists on `ScriptManager`.

#### F-0013 - Script.created_at uses naive datetime.now while last_run uses UTC

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 295-331
- **Pattern:** Cat 21
- **Excerpt:**

  ```python
  created_at: datetime = field(default_factory=datetime.now)
  ...
  self.execution_results["last_run"] = datetime.now(tz=UTC).isoformat()
  ```

- **Why this is non-functional:** Mixing tz-aware and tz-naive datetimes causes `TypeError` on subtraction.

### Category 22 - Test / Debug Code Leaked

#### F-0014 - Inline comment in reload_script admits broken implementation

- **File:** `src/intellicrack/core/script_gen.py`
- **Lines:** 690-692
- **Pattern:** Cat 22
- **Excerpt:**

  ```python
      # First try to find where it might be saved
      # This is a bit tricky since save_script logic handles paths
      # We assume standard location in scripts_dir
      _logger.debug("script_reload_start", script=name)
  ```

- **Why this is non-functional:** Apology comments left in production. CLAUDE.md forbids TODO comments.

### Category 24 - Recovery / Robustness Theater

#### F-0015 - AnalysisAggregator continues with BinaryInfo only and reports a "summary" that may be empty

- **File:** `src/intellicrack/core/analysis_aggregator.py`
- **Lines:** 95-120
- **Pattern:** Cat 24
- **Excerpt:**

  ```python
  if not source_bridges:
      source_bridges.append("binary_info")
      notes.append("No bridges connected; using BinaryInfo metadata only")
  ...
  return BridgeAnalysisSummary(
      binary_name=binary_name,
      strings=strings,
      ...
      source_bridges=source_bridges,
      analysis_notes=notes,
  )
  ```

- **Why this is non-functional:** When no bridge contributed, returns summary with empty strings/functions but appears successful. AI report generation produces empty report presented as authoritative.
