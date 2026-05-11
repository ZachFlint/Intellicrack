> # Workgroup Directive — Execution Order 01/23: `bridges-hex`
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
# Findings: bridges-hex

## Files audited (2)

- src/intellicrack/bridges/hex_editor.py
- src/intellicrack/bridges/hex_state.py

## Summary

60 findings across 24 categories. Major themes: a fundamentally broken Python "sandbox" in `run_python_script` (real RCE), naive ClamAV/DIE signature scanners that misimplement the formats, missing Mach-O support contradicting advertised capabilities, full-document memory loads that defeat the memory-mapped Rust backend, BPS encoder degenerate to suboptimal output, broken UTF-16 string scanner, and pervasive "fake success" returns when backend methods are missing.

## Findings

### Category 14 - Security / Crypto Failures

#### F-0001 - `run_python_script` "sandbox" is escapable; permits subprocess.Popen and os.system via **subclasses**

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5667-5872 (esp. 5802-5825)
- **Pattern:** Cat 14, Cat 3
- **Why this is non-functional:** Excludes only six builtins. `object`, `type`, `getattr`, `globals`, `__build_class__`, `vars`, `setattr` all remain. A user/LLM script can trivially escape via `().__class__.__base__.__subclasses__()` to obtain `subprocess.Popen` or `os.system`. This is a Windows RCE vector exposed to LLM tool calls.

### Category 2 - Hardcoded Return Values & Fake Success

#### F-0002 - set_va_base claims success when backend lacks add_va_mapping

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4631-4668
- **Pattern:** Cat 2

#### F-0003 - set_chunk_size and set_memory_budget return True regardless of effect

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5874-5919
- **Pattern:** Cat 2

### Category 20 - Dead Code

#### F-0004 - `_alignment_grid_size` is written and never read

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5451-5464, 345
- **Pattern:** Cat 20, Cat 18

### Category 7 - Concurrency

#### F-0005 - `_state_lock` only acquired in shutdown; meaningless elsewhere

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 347, 1569
- **Pattern:** Cat 7

### Category 9 - Bridge Integration

#### F-0006 - `apply_transform` and `apply_pipeline` return transformed bytes but never write back

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3318-3368, 3370-3418
- **Pattern:** Cat 9

### Category 19 - Data Parsing

#### F-0007 - `_build_ips_from_patches` overflow handling broken

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3621-3682, 3799-3830
- **Pattern:** Cat 19

#### F-0008 - `_apply_ips_patches` premature break + project-invented EOF marker

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3832-3893
- **Pattern:** Cat 19, Cat 5

### Category 14 - Security

#### F-0009 - MD5 of full file in memory defeats memory-mapped backend

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6080
- **Pattern:** Cat 14

### Category 4 - Naive Implementations

#### F-0010 - ClamAV NDB scanner strips wildcards, defeating signatures

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6044-6172
- **Pattern:** Cat 4

#### F-0011 - DIE scanner is a fundamental loss of capability

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5945-6042
- **Pattern:** Cat 4

### Category 15 - Platform

#### F-0012 - list_process_regions docstring says Windows-only, no actual platform check

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4133-4184
- **Pattern:** Cat 15

### Category 16 - Binary Analysis

#### F-0013 - get_pe_imports/get_pe_exports load full document into memory

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3203-3248, 3250-3316
- **Pattern:** Cat 16

#### F-0014 - yara_scan loads entire document into memory

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3023-3110
- **Pattern:** Cat 16

#### F-0015 - PE checksum offset hardcoded inline despite available constants

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5485-5516
- **Pattern:** Cat 19

### Category 5 - Error Handling

#### F-0016 - Pattern registry unavailable returns empty list, indistinguishable from no matches

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2235-2256, 2258-2291
- **Pattern:** Cat 5

### Category 13 - Logging Theater

#### F-0017 - apply_template doesn't notify state holder

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2002-2025
- **Pattern:** Cat 13, Cat 18

### Category 5 - Error Handling

#### F-0018 - _apply_arithmetic_fallback silently returns input unchanged for xor/and/or without key

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4515-4520
- **Pattern:** Cat 5

### Category 16 - Binary Analysis

#### F-0019 - entropy/digram_matrix etc. require exact Rust attribute names with no fallback

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2831-2929
- **Pattern:** Cat 16

### Category 4 - Naive

#### F-0020 - read_bytes registered as LLM tool with no length cap

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1633-1653
- **Pattern:** Cat 4

### Category 13 - Logging Theater

#### F-0021 - Wholesale "everything from 0 to length changed" event after every modification

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1882-1907
- **Pattern:** Cat 13

#### F-0022 - State holder notified that entire document changed even when script didn't write

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5868-5871
- **Pattern:** Cat 13

### Category 16 - Binary Analysis

#### F-0023 - Mach-O missing despite supported_formats=["pe","elf","macho","raw"]

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5076-5099, 5164
- **Pattern:** Cat 16

### Category 23 - Build/Release Metadata

#### F-0024 - Capabilities advertise macho/scripting that aren't real

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 348-354
- **Pattern:** Cat 23

### Category 16 - Binary Analysis

#### F-0025 - Mach-O magics return [] silently in auto_detect_va_mappings

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4710-4734
- **Pattern:** Cat 16

### Category 5 - Error Handling

#### F-0026 - PE structure bookmarks left half-applied on failure

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5113-5132
- **Pattern:** Cat 5

### Category 12 - Configuration

#### F-0027 - set_display_mode/set_color_mode don't validate against documented enum

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4108-4131, 5921-5934
- **Pattern:** Cat 12

### Category 4 - Naive

#### F-0028 - snap_to_alignment only floors despite "snap to nearest" docstring

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5433-5449
- **Pattern:** Cat 4

### Category 19 - Data Parsing

#### F-0029 - UTF-16LE scanner only checks even starting offsets

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5050-5071
- **Pattern:** Cat 19

### Category 4 - Naive

#### F-0030 - BPS encoder degenerate; only emits SourceRead and TargetRead

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6428-6492
- **Pattern:** Cat 4

### Category 21 - Documentation Drift

#### F-0031 - toggle_bit Rust path doesn't emit log; fallback path does

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4593-4629
- **Pattern:** Cat 21

### Category 6 - Resource Lifecycle

#### F-0032 - open_file doesn't close previous document; leaks mmap

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1577-1612
- **Pattern:** Cat 6

#### F-0033 - save_to_sandbox leaks created sandbox instance on copy_to failure

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2677-2754
- **Pattern:** Cat 6

### Category 17 - AI Provider

#### F-0034 - get_context_for_ai returns unbounded bookmark list

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2625-2675
- **Pattern:** Cat 17

### Category 5 - Error Handling

#### F-0035 - export_ips_patches falls back silently for ips32 path mismatch

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3669-3679
- **Pattern:** Cat 5

### Category 7 - Concurrency

#### F-0036 - hex_state_notify guard silently drops downstream events

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 560-599
- **Pattern:** Cat 7

#### F-0037 - hex_state set_document reads length outside the lock

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 191-227
- **Pattern:** Cat 7

#### F-0038 - hex_state asymmetric locking on display_mode getter/setter

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 337-355
- **Pattern:** Cat 7

#### F-0039 - hex_state property getters read shared state without lock

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 110-126
- **Pattern:** Cat 7

### Category 16 - Binary Analysis

#### F-0040 - UTF-16 scanner accepts code units like 0x2070 as printable

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5050-5071
- **Pattern:** Cat 16

### Category 5 - Error Handling

#### F-0041 - search_text_encoded falls through silently if Rust path raises

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1853-1856
- **Pattern:** Cat 5

### Category 6 - Resource Lifecycle

#### F-0042 - BPS/UPS export loads original + current docs simultaneously

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6248-6370
- **Pattern:** Cat 6

### Category 5 - Error Handling

#### F-0043 - ClamAV DB load raises uncaught AttributeError on dict-shaped DB

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5962-5963
- **Pattern:** Cat 5

#### F-0044 - ClamAV dispatch by suffix only; .cdb/.mdb/.fp etc. mishandled

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6063-6068
- **Pattern:** Cat 5

### Category 22 - Test/Debug Code

#### F-0045 - run_python_script forbidden_builtins set looks like a hand-rolled prototype

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5802
- **Pattern:** Cat 22

### Category 18 - GUI/UX

#### F-0046 - copy_as silently copies one byte at cursor when no selection

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2401-2407
- **Pattern:** Cat 18

### Category 5 - Error Handling

#### F-0047 - base_convert raises uncaught ValueError on bad input

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5594-5625
- **Pattern:** Cat 5

### Category 6 - Resource Lifecycle

#### F-0048 - initialize replaces local cache, dropping bridge-side rules

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1531-1546
- **Pattern:** Cat 6

#### F-0049 - save_as doesn't update target_path

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2526-2570
- **Pattern:** Cat 6

### Category 14 - Security

#### F-0050 - export_annotated_html only escapes 3 chars; bookmark color XSS

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5283-5295
- **Pattern:** Cat 14

### Category 17 - AI Provider

#### F-0051 - get_digram_matrix returns 65536 integers (~400 KB JSON) per call

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2913-2929
- **Pattern:** Cat 17

### Category 4 - Naive

#### F-0052 - CRC fallback bit-by-bit Python; no zlib/binascii fallback

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3606-3616
- **Pattern:** Cat 4

### Category 9 - Bridge Integration

#### F-0053 - fpdf module lazy-import without runtime availability check

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6756-6760
- **Pattern:** Cat 9

### Category 21 - Documentation Drift

#### F-0054 - search_numeric accepts unknown value_type, silently treats as uint

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3895-3949
- **Pattern:** Cat 21

### Category 24 - Recovery Theater

#### F-0055 - open_process_memory doesn't close any previously open document

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4173-4184
- **Pattern:** Cat 24

### Category 5 - Error Handling

#### F-0056 - get_pe_imports DIRECTORY_ENTRY default 1/0 magic fallback

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3219-3220, 3291-3292
- **Pattern:** Cat 5

### Category 11 - State

#### F-0057 - target_path constructed twice; can drift from Rust file_path()

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1600-1606
- **Pattern:** Cat 11

#### F-0058 - hex_state clear_all clears highlights but only emits DOCUMENT_CLOSED

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 280-301
- **Pattern:** Cat 11

### Category 5 - Error Handling

#### F-0059 - run_python_script catches MemoryError; SystemExit uncaught; OverflowError missing

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5834-5855
- **Pattern:** Cat 5

### Category 21 - Documentation Drift

#### F-0060 - safe_print ignores file= kwarg; no size cap on capture

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5805-5819
- **Pattern:** Cat 21
