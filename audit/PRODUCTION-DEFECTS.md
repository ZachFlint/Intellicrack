# Production Defects Surfaced by Strengthened Test Gates

The offender-remediation workflow ran under a strict **test-only** policy and
left now-genuine tests **correct-and-red** where they exposed real `src/` bugs.
Those bugs were then triaged and (per the user's later direction) **fixed**.

**Status legend:**
- **FIXED** — production code corrected; the gating test now passes.
- **NOT-REPRODUCED** — writer-claimed, but the gating test passes on a normal host; not a real defect here.

Last verified 2026-06-12.

---

## P-001 — PE checksum repair broadcast the wrong byte offset  ·  FIXED

- **Severity:** Medium (correctness / UI-state integrity)
- **Production symbol:** `HashingMixin._on_repair_pe_checksum`
- **Location:** `src/intellicrack/ui/panels/hex_editor/hashing.py`
- **Gating test:** `tests/test_audit4/c6_hex_hashing/test_hashing.py::TestRepairPeChecksumFiresNotify::test_repair_notifies_correct_bytes` (and `test_insert_hash_fires_notify`)
- **Was:** `notify_data_modified` fired with a hardcoded `_PE_CHECKSUM_OFFSET = 0x58`, correct only when `e_lfanew == 0`; observers redrew the wrong four bytes for any normally-laid-out PE.
- **Fix:** added `HashingMixin._pe_checksum_field_offset()` which reads `e_lfanew`
  from the document (validating the `MZ` and `PE\0\0` signatures and bounds) and
  computes `e_lfanew + 4 + 20 + 64` — the `CheckSum` field offset for both PE32
  and PE32+. The repair now notifies the real offset (`0x98` for the
  `e_lfanew=0x40` test image). Removed the misleading `_PE_CHECKSUM_OFFSET` constant.
- **Test reconciliation:** a second test (`test_insert_hash_fires_notify`) had
  codified the bug (asserted `0x58`); it and a stale `_PRODUCTION_NOTIFY_OFFSET`
  constant were corrected to assert the derived `0x98`, and the now-false
  "failing-as-designed" docstrings updated. **All 9 hashing tests pass.**

---

## PD-001 — ai_brain.svg missing root width/height attributes  ·  FIXED

- **Severity:** Low (icon rendering in high-DPI / dense layouts)
- **Production symbol / location:** `src/intellicrack/assets/icons/ai_brain.svg`
- **Gating test:** `tests/test_ui/test_icon_manager.py::TestAllMappedIconsLoad::test_all_mapped_icons_load_svg_root_width_and_height_attributes`
- **Was:** root had `viewBox='0 0 24 24'` but no `width`/`height`, so Qt could
  render it at an uncontrolled natural size (the only icon of 71 lacking them).
- **Fix:** added `width="24" height="24"` to the root element, matching the other
  70 icons. **Icon-manager tests pass.**

---

## PD-01 / PD-02 — clipboard_monitor.ps1  ·  NOT-REPRODUCED

The writer logged two clipboard-monitor defects (Add-Type failing on .NET 10;
fallback `Get-Clipboard` empty in a headless subprocess). The genuine
end-to-end gate
`tests/test_audit3/sandbox/test_clipboard_monitor.py::test_smoke_script_logs_clipboard_change`
(real `Set-Clipboard` write, real `clipboard_monitor.ps1` subprocess, 7-field
pipe-delimited record with an independent UTF-8 byte-count oracle) **passes on
this Windows 11 host**; all 10 clipboard tests pass. The claims stem from a
constrained/headless agent context (no window station) and are not defects of
the production script on a normal Windows session. **No production change made.**
The two clipboard-test docstring NOTEs still describe the test as red — stale;
a docstring-accuracy follow-up.

---

## Result

All confirmed production defects are **FIXED**: 0 red-by-design tests remain.
The full audit-touched re-run shows no failure attributable to these fixes.
