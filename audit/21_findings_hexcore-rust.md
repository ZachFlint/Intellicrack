> # Workgroup Directive — Execution Order 21/23: `hexcore-rust`
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
# Findings: hexcore-rust

## Files audited (22)

- src/intellicrack-hexcore/Cargo.toml
- src/intellicrack-hexcore/intellicrack_hexcore.pyi
- src/intellicrack-hexcore/src/lib.rs
- src/intellicrack-hexcore/src/bps_ups.rs
- src/intellicrack-hexcore/src/data_inspector.rs
- src/intellicrack-hexcore/src/data_source.rs
- src/intellicrack-hexcore/src/diff.rs
- src/intellicrack-hexcore/src/encodings.rs
- src/intellicrack-hexcore/src/entropy.rs
- src/intellicrack-hexcore/src/hash.rs
- src/intellicrack-hexcore/src/mmap_io.rs
- src/intellicrack-hexcore/src/patch_export.rs
- src/intellicrack-hexcore/src/piece_table.rs
- src/intellicrack-hexcore/src/search.rs
- src/intellicrack-hexcore/src/strings.rs
- src/intellicrack-hexcore/src/transforms.rs
- src/intellicrack-hexcore/src/undo.rs
- src/intellicrack-hexcore/src/templates/mod.rs
- src/intellicrack-hexcore/src/templates/common.rs
- src/intellicrack-hexcore/src/templates/elf.rs
- src/intellicrack-hexcore/src/templates/eval.rs
- src/intellicrack-hexcore/src/templates/json_schema.rs
- src/intellicrack-hexcore/src/templates/macho.rs
- src/intellicrack-hexcore/src/templates/pe.rs
- src/intellicrack-hexcore/src/templates/zip.rs

## Findings

### Category 6 - Resource & Lifecycle Issues

#### F-0001 - `move_block` clears source without recording undo for the source clear

- **File:** `src/intellicrack-hexcore/src/lib.rs`
- **Lines:** 843-861
- **Pattern:** Cat 6, "Asymmetric / partial state mutation that breaks undo"
- **Excerpt:**

  ```rust
  fn move_block(&mut self, src_offset: usize, length: usize, dst_offset: usize) -> PyResult<()> {
      let doc_len = self.inner.document_size();
      if src_offset + length > doc_len || dst_offset + length > doc_len {
          return Err(pyo3::exceptions::PyValueError::new_err(
              "block exceeds document size",
          ));
      }
      let data = self.inner.read(src_offset, length);
      let old_dst = self.inner.read(dst_offset, length);
      let zeros = vec![0u8; length];
      self.inner.overwrite(src_offset, &zeros);
      self.inner.overwrite(dst_offset, &data);
      self.undo_mgr.record(undo::Operation::Overwrite {
          offset: dst_offset,
          old_data: old_dst,
          new_data: data,
      });
      Ok(())
  }
  ```

- **Why this is non-functional:** Two byte-region mutations are performed (src zeroed, dst overwritten) but only one `Operation::Overwrite` is recorded - the destination one. There is no undo record for the source-clear write. Calling `undo()` after `move_block` will only restore the destination region; the source bytes will remain zeroed. This leaves the document in an inconsistent state that cannot be returned to the original via `undo()`. It also breaks `is_modified()` accounting symmetry.
- **Callers / blast radius:** `src/intellicrack/bridges/hex_editor.py:4315`, `src/intellicrack/ui/panels/hex_editor/_transforms.py:774`.
- **Suggested remediation summary:** Record both `Operation::Overwrite` events as a single composite, or add a `MoveBlock` undo variant that captures both regions.

### Category 14 - Silent Data Corruption

#### F-0002 - `swap_blocks` silently zero-pads when blocks have different lengths

- **File:** `src/intellicrack-hexcore/src/lib.rs`
- **Lines:** 879-886
- **Pattern:** Cat 6, Cat 14
- **Excerpt:**

  ```rust
  let data_a = self.inner.read(offset_a, len_a);
  let data_b = self.inner.read(offset_b, len_b);
  let mut write_a: Vec<u8> = data_b.clone();
  write_a.resize(len_a, 0);
  let mut write_b: Vec<u8> = data_a.clone();
  write_b.resize(len_b, 0);
  self.inner.overwrite(offset_a, &write_a);
  self.inner.overwrite(offset_b, &write_b);
  ```

- **Why this is non-functional:** When `len_a != len_b`, `write_a.resize(len_a, 0)` truncates or zero-pads `data_b` to fit slot A. This destroys the trailing bytes of the longer block instead of performing a true swap. There is no length-equality check.
- **Callers / blast radius:** `src/intellicrack/bridges/hex_editor.py:4364`, `src/intellicrack/ui/panels/hex_editor/_transforms.py:790`.
- **Suggested remediation summary:** Reject unequal lengths with an error, or perform real insert/delete swap via piece table.

### Category 22 - Dead Code

#### F-0003 - `diff_data_block` block-level fallback is dead code

- **File:** `src/intellicrack-hexcore/src/diff.rs`
- **Lines:** 338-431 (specifically the post-anchored fallback at 348-430)
- **Pattern:** Cat 22, Cat 20
- **Excerpt:**

  ```rust
  fn diff_data_block(data_a: &[u8], data_b: &[u8]) -> DiffResult {
      if data_a == data_b {
          return identical_result(data_a.len());
      }

      let anchored = diff_data_anchored(data_a, data_b);
      if !anchored.regions.is_empty() {
          return anchored;
      }

      let blocks_a: Vec<&[u8]> = data_a.chunks(BLOCK_SIZE).collect();
      let blocks_b: Vec<&[u8]> = data_b.chunks(BLOCK_SIZE).collect();
      let ops = capture_diff_slices(Algorithm::Myers, &blocks_a, &blocks_b);
  ```

- **Why this is non-functional:** `diff_data_anchored` always pushes at least one region for non-identical inputs. The only path where `anchored.regions` could be empty is `data_a == data_b`, which is short-circuited above. Therefore the entire 64-byte block-level Myers fallback is unreachable.
- **Callers / blast radius:** `src/intellicrack-hexcore/src/lib.rs:1097`.
- **Suggested remediation summary:** Either delete the fallback or change the condition that gates entering it.

### Category 7 - Silent Errors

#### F-0004 - `eval_pointer` swallows recursive-evaluation errors

- **File:** `src/intellicrack-hexcore/src/templates/eval.rs`
- **Lines:** 367-387
- **Pattern:** Cat 7, Cat 5
- **Excerpt:**

  ```rust
  let children = if ptr_value < self.data.len() && self.depth < MAX_DEPTH {
      if let Some(template) = self.registry.get(target_template) {
          ...
          let result = self.evaluate_fields(&template.fields);
          ...
          result.unwrap_or_default()
      } else {
          Vec::new()
      }
  } else {
      Vec::new()
  };
  ```

- **Why this is non-functional:** When dereferencing a `Pointer` field, the recursive `evaluate_fields` call's `Result` is collapsed via `result.unwrap_or_default()`. Any `TemplateError` raised by the pointed-at template is silently dropped. Compare to `eval_struct_ref` which uses `?` to propagate template errors.
- **Suggested remediation summary:** Use `?` to propagate template errors; or attach an error indicator to the parsed field.

### Category 14 - Silent Zero Result

#### F-0005 - `sizeof()` silently returns 0 for unknown type names

- **File:** `src/intellicrack-hexcore/src/templates/eval.rs`
- **Lines:** 905-912
- **Pattern:** Cat 14, Cat 5
- **Excerpt:**

  ```rust
  let size = match type_name.as_str() {
      "u8" | "uint8" | "int8" | "s8" | "bool" | "char" => 1,
      "u16" | "uint16" | "int16" | "s16" => 2,
      "u32" | "uint32" | "int32" | "s32" | "float" | "float32" => 4,
      "u64" | "uint64" | "int64" | "s64" | "double" | "float64" => 8,
      _ => 0,
  };
  return Ok(size);
  ```

- **Why this is non-functional:** Inside template `Computed` expressions, `sizeof(unknown_or_typo)` returns 0 with no error. A user-authored JSON template using `sizeof(uint128)` or `sizeof(SomeStruct)` silently substitutes 0 into the surrounding arithmetic, producing zero-element dynamic arrays without flagging the typo.
- **Suggested remediation summary:** Error on unknown type names, or look them up against registered structs.

## Notes on inspected items that are NOT findings

- All `unreachable!()` calls (transforms.rs, hash.rs, bps_ups.rs) sit after exhaustive matches whose dispatch is statically verified.
- `let _ =` occurrences in `mmap_io.rs:267-268` are test-only cleanup; in `hash.rs:115` and `patch_export.rs:177` they discard `fmt::Write` results that are infallible for `String`.
- Non-Windows arms of `from_process_memory` / `list_process_memory_regions` (`lib.rs:733-739, 757-763`) intentionally return a `PyRuntimeError` rather than canned data - this is correct platform-gating.
- The `iso10126` padding using zero filler with the length byte is documented as deterministic by design; decryption only relies on the trailing length byte.
- Search/diff/template parsers all do real work; PE-checksum, BPS/UPS, IPS/IPS32/COD all parse and produce real bytes, validated by extensive `#[cfg(test)] mod tests` blocks.
