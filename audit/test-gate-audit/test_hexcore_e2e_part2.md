# Test-Gate Audit — test_hexcore_e2e (part 2)

## Summary
- Files audited: 34
- Test functions examined: 558 (parametrized families counted once per function)
- Genuine gates: 548
- Flagged non-gates: 10  (CRITICAL: 1, HIGH: 4, MEDIUM: 0, LOW: 5)

## Coverage checklist
- [x] tests/test_hexcore_e2e/test_bridge_strings.py — gates: 8, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_structure_bookmarks.py — gates: 6, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_transforms.py — gates: 6, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_transforms_deep.py — gates: 17, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_va_mapping.py — gates: 10, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_yara.py — gates: 7, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_yara_deep.py — gates: 14, flagged: 0
- [x] tests/test_hexcore_e2e/test_data_inspector.py — gates: 27, flagged: 0
- [x] tests/test_hexcore_e2e/test_document_lifecycle.py — gates: 16, flagged: 0
- [x] tests/test_hexcore_e2e/test_encodings.py — gates: 23, flagged: 1
- [x] tests/test_hexcore_e2e/test_entropy.py — gates: 30, flagged: 0
- [x] tests/test_hexcore_e2e/test_hashing.py — gates: 27, flagged: 0
- [x] tests/test_hexcore_e2e/test_hex_document_state.py — gates: 70, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexcore_rust_audit1.py — gates: 13, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py — gates: 25, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexpat_complex_patterns.py — gates: 30, flagged: 1
- [x] tests/test_hexcore_e2e/test_hexpat_control_flow.py — gates: 19, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexpat_data_reader.py — gates: 33, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexpat_evaluator.py — gates: 34, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexpat_parser_e2e.py — gates: 25, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexpat_pattern_registry.py — gates: 21, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexpat_preprocessor.py — gates: 28, flagged: 0
- [x] tests/test_hexcore_e2e/test_hexpat_stdlib.py — gates: 53, flagged: 1
- [x] tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py — gates: 78, flagged: 0
- [x] tests/test_hexcore_e2e/test_patch_export.py — gates: 15, flagged: 0
- [x] tests/test_hexcore_e2e/test_process_memory.py — gates: 11, flagged: 1
- [x] tests/test_hexcore_e2e/test_read_write_ops.py — gates: 23, flagged: 0
- [x] tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py — gates: 22, flagged: 0
- [x] tests/test_hexcore_e2e/test_realcov_09b_stdlib_realbin.py — gates: 24, flagged: 0
- [x] tests/test_hexcore_e2e/test_realcov_09b_typesystem_completer.py — gates: 25, flagged: 0
- [x] tests/test_hexcore_e2e/test_search.py — gates: 28, flagged: 1
- [x] tests/test_hexcore_e2e/test_templates.py — gates: 42, flagged: 2
- [x] tests/test_hexcore_e2e/test_transforms.py — gates: 22, flagged: 0
- [x] tests/test_hexcore_e2e/test_undo_redo.py — gates: 14, flagged: 0

## Flagged tests

### tests/test_hexcore_e2e/test_hexpat_complex_patterns.py
#### `test_cast_negative_to_signed` — CRITICAL — N1 (no-assert)
- **Location:** tests/test_hexcore_e2e/test_hexpat_complex_patterns.py:388
- **Current behavior:** Packs `-1` as an s8, runs `interp.execute_bytes("s8 val @ 0;\n", data)`, and discards the result. There is no `assert` of any kind. The test name claims to verify "casting a negative integer to s8 preserves the sign bit," but nothing checks the decoded value, sign, or even that a field was produced.
- **Why it is not a gate:** As long as `execute_bytes` does not raise, the test passes regardless of whether the s8 was decoded as `-1`, `255`, or anything else. A sign-extension regression — the exact thing the name targets — would not turn it red.
- **Recommended fix:** Capture the result and assert the decoded value, e.g. `results = interp.execute_bytes("s8 val @ 0;", data); val = next(r for r in results if r["name"] == "val"); assert val["display_value"] == "-1"; assert val["raw_bytes"] == [0xFF]`.

### tests/test_hexcore_e2e/test_templates.py
#### `test_pe_template_on_elf_data_parses_or_raises` — HIGH — N2/N6 (swallowed failure + vacuously-satisfiable conditional)
- **Location:** tests/test_hexcore_e2e/test_templates.py:627
- **Current behavior:** Wraps `apply_template("IMAGE_DOS_HEADER", 0)` in `try/except (RuntimeError, ValueError)` that sets `parsed_successfully = False`, then runs the meaningful assertions (field present, e_magic NOT containing the MZ value) only inside `if parsed_successfully:`. If the production code raises — or silently returns `[]` after the helper sets the flag — the assertion block is skipped entirely.
- **Why it is not a gate:** Both branches pass: a raise is swallowed and asserts nothing; a parse runs the assertion. A regression where applying a PE template to ELF data crashes with an unexpected error, or returns an empty list, slips through because the only real checks are conditional on the success branch.
- **Recommended fix:** Decide the contract and pin it. Either assert the template raises a specific exception type on mismatched data with `pytest.raises`, or always assert the parse succeeded and `e_magic` does not hold the MZ value — do not branch the assertions on whether an exception happened.

#### `test_elf_template_on_pe_data_parses_or_raises` — HIGH — N2/N6 (swallowed failure + vacuously-satisfiable conditional)
- **Location:** tests/test_hexcore_e2e/test_templates.py:651
- **Current behavior:** Mirror of the previous test for `Elf64_Ehdr` on PE bytes. `try/except` sets `parsed_successfully=False`; the `e_ident` checks run only under `if parsed_successfully:`.
- **Why it is not a gate:** Identical defect — the exception path performs no assertion and the only checks are guarded by the success flag, so a crash or empty result silently passes.
- **Recommended fix:** Same as above — assert a concrete exception type on the error path with `pytest.raises`, or unconditionally assert the parse occurred and `e_ident` lacks the ELF magic.

### tests/test_hexcore_e2e/test_bridge_transforms_deep.py
#### `test_pipeline_with_invalid_step_name_completes` — HIGH — N6/N2 (vacuously-satisfiable conditional)
- **Location:** tests/test_hexcore_e2e/test_bridge_transforms_deep.py:270
- **Current behavior:** Runs `apply_pipeline` with an unknown step name inside `try/except (RuntimeError, ValueError, KeyError)`. The only assertion is `if raised is None: assert result is not None`. If the bridge raises, `raised` is set and no assertion executes; if it returns, the assertion is merely `result is not None`.
- **Why it is not a gate:** Every outcome passes — raising is accepted with no check, and a successful return is accepted on the weakest possible `is not None`. The docstring claims unknown steps are "silently skipped; the result is the remaining output," but that claim is never verified (the remaining output is never compared to the expected unchanged bytes).
- **Recommended fix:** Pin the documented behavior. If unknown steps are skipped, assert `result == binascii.hexlify(payload).decode()` (input unchanged). If the contract is to raise, use `pytest.raises(<specific exc>)`. Remove the dual-outcome branch.

### tests/test_hexcore_e2e/test_search.py
#### `test_wildcard_byte_matches_pe_header_sequence` — HIGH — N3 (skip on the feature under test)
- **Location:** tests/test_hexcore_e2e/test_search.py:99
- **Current behavior:** Calls `doc.search_hex("4D ?? 90", 100)` inside `try/except (RuntimeError, ValueError): pytest.skip("wildcard hex search not supported by this build")`. The wildcard search capability is exactly what the test names and claims to verify.
- **Why it is not a gate:** If wildcard hex search breaks or is dropped from the build, the test skips green instead of failing. A production gate for a shipped capability must hard-require it; a regression that removes wildcard support would be masked as a skip.
- **Recommended fix:** Remove the skip-on-error wrapper and assert the match directly (`results = doc.search_hex("4D ?? 90", 100); assert results and results[0][0] == 0`). If wildcard support is genuinely optional per build, gate the whole module on a capability probe at import time rather than swallowing the error of the operation under test.

### tests/test_hexcore_e2e/test_bridge_transforms.py
#### `test_apply_transform_returns_length_matching_input` — LOW — weak gate
- **Location:** tests/test_hexcore_e2e/test_bridge_transforms.py:129
- **Current behavior:** XORs 16 bytes with key `00` and asserts only `len(result) == 32` (hex-char length). It never asserts the bytes are unchanged, even though key `00` makes the output exactly the input.
- **Why it is weaker than it should be:** A transform that returned garbage of the correct length would pass. The sibling exact-value tests in this file (`test_apply_transform_xor_single_known_output`) gate content, so this one's length-only check is a redundant weak gate that does not catch a value regression on the same op.
- **Recommended fix:** Assert `result == "aa" * 16` (XOR of `0xAA` with `0x00` is `0xAA`), turning the length check into a content check.

### tests/test_hexcore_e2e/test_bridge_yara.py
#### `test_yara_scan_returns_list` — LOW — N8 (existence/type-only)
- **Location:** tests/test_hexcore_e2e/test_bridge_yara.py:79
- **Current behavior:** Asserts only `isinstance(results, list)` for a scan that, on the loaded PE with the MZ rule, must actually match.
- **Why it is weaker than it should be:** A broken `yara_scan` that always returned `[]` would still satisfy `isinstance(..., list)`. The very next test (`test_yara_scan_mz_rule_matches_pe_file`) does gate the match, so this one only adds a type check that cannot catch a content regression.
- **Recommended fix:** Either drop it as redundant or strengthen to assert the match is present (`assert results and results[0]["rule"] == "MZHeader"`).

### tests/test_hexcore_e2e/test_encodings.py
#### `test_decode_invalid_utf8_does_not_crash` — LOW — N2/N7 (swallowed failure / accepts both outcomes)
- **Location:** tests/test_hexcore_e2e/test_encodings.py:325
- **Current behavior:** Decodes invalid UTF-8 inside `try/except (ValueError, RuntimeError)`; the only assertion runs `if raised is None:` and just checks the result is a non-None `str`. A raise sets `raised` and asserts nothing.
- **Why it is weaker than it should be:** Both outcomes pass and neither pins a value. The intent ("returns replacement characters or raises a predictable exception") is plausible but the test does not assert *which* replacement characters appear nor *which* exception type, so a regression that silently returns wrong text or a wrong exception is not caught. Narrow concern (genuine ambiguity in the contract), hence LOW.
- **Recommended fix:** Resolve the contract: if replacement is used, assert the decoded string equals the known replacement-char output; if it raises, assert the specific exception with `pytest.raises`. Do not accept both.

### tests/test_hexcore_e2e/test_process_memory.py
#### `test_from_process_memory_zero_size_handled` — LOW — N7 (accepts both outcomes)
- **Location:** tests/test_hexcore_e2e/test_process_memory.py:181
- **Current behavior:** Reads zero bytes from a process region inside `try/except OSError`; passes either way — on `OSError` it sets `raised=True` and asserts nothing, otherwise asserts `doc.length() == 0`.
- **Why it is weaker than it should be:** The "raises or returns empty" dual contract means a regression that, say, returned a 4096-byte document for a zero-size request is the only thing this catches; a wrong exception type or a hang is not gated. Narrow OS-boundary concern, hence LOW. (The Windows-only skip and the `_find_readable_region`/`pytest.skip` for no readable region are legitimate environment-capability skips, listed below.)
- **Recommended fix:** Pick the actual native contract and assert it exactly — either `pytest.raises(OSError)` or `doc.length() == 0`, not both.

### tests/test_hexcore_e2e/test_hexpat_stdlib.py
#### `test_format_via_interpreter_produces_string` — LOW — stale/mislabeled (does not exercise format())
- **Location:** tests/test_hexcore_e2e/test_hexpat_stdlib.py:599
- **Current behavior:** Despite the name and docstring ("`format()` call from pattern source returns a string without error"), the pattern source is `"u8 ok @ 0;"` — there is no `format()` call at all. It only asserts a plain field was parsed.
- **Why it is weaker than it should be:** It gates `execute_bytes` of a trivial field (which dozens of other tests already cover) but provides zero coverage of `format()`, the behavior its name claims. A `format()` regression would never trip it. Low severity because it still asserts a real (if unrelated) value.
- **Recommended fix:** Put a real `format()` call in the source and assert the produced string, e.g. via a pattern that surfaces the formatted output, or remove the test as a duplicate of `test_print_via_interpreter_no_crash`.

## Acceptable skips (not flagged)
- tests/test_hexcore_e2e/test_process_memory.py:19 `_WIN32_ONLY` — Windows-only process-memory API; skipping on non-Windows is a legitimate platform-capability skip.
- tests/test_hexcore_e2e/test_process_memory.py:146,164,198 `pytest.skip("No suitable/accessible readable memory region ...")` — environment-capability skip when the current process exposes no readable region of the requested size; the read capability itself is still gated by the regions that do exist.
- tests/test_hexcore_e2e/test_realcov_09b_stdlib_realbin.py:180 `pytest.skip("DOS stub message absent from this PE variant")` — data-availability skip for a specific real PE variant; the builtin's offset contract is still asserted whenever the stub is present.
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:97,114,156,178,193 `skipif(not _has_native_va_mapping())` — capability probe for an optional native API; legitimate, and the auto-detect tests that exercise the same machinery via the bridge are not gated behind it.
- Module-level `pytest.importorskip("intellicrack_hexcore" / "yara" / hexpat modules)` across the suite — build/dependency-availability skips for the native module and optional yara dependency; legitimate environment skips, not masking of the behavior under test.
- The `xor_single`/`bitwise_not`/`rot13`/`base64_encode` transform-availability `pytest.skip` calls in test_bridge_transforms.py and test_bridge_transforms_deep.py probe whether a named transform is registered before exercising it; these are capability probes for optional registry entries rather than masking a failure of the operation under test, so they are not flagged. (test_transforms.py separately gates the exact registry contents at line 21–47, so a dropped transform is still caught there.)
