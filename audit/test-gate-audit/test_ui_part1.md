# Test-Gate Audit — test_ui (part 1)

## Summary
- Files audited: 31
- Test functions examined: 274
- Genuine gates: 256
- Flagged non-gates: 18  (CRITICAL: 0, HIGH: 0, MEDIUM: 7, LOW: 11)

The test_ui (part 1) corpus is strong. The overwhelming majority of tests drive
real Qt widgets, real PE/ELF/Mach-O fixtures (kernel32.dll, System32 EXE), real
capstone/pefile disassembly, real YARA scans, real structlog pipelines, and the
real hexcore backend, asserting exact values against independent oracles. The
flagged items are almost all weak type/existence-only checks that sit *next to*
a companion test which genuinely gates the same behavior, so the real coverage
is not lost — they are simply redundant and should either be hardened or
removed. No CRITICAL or HIGH non-gates were found. `launch_splash_demo.py` is a
visual demo script (no test functions) and is excluded from the function count.

## Coverage checklist
- [x] tests/test_ui/__init__.py — gates: 0, flagged: 0 (docstring-only module)
- [x] tests/test_ui/conftest.py — gates: 0, flagged: 0 (fixtures/helpers only)
- [x] tests/test_ui/launch_splash_demo.py — gates: 0, flagged: 0 (visual demo, no tests)
- [x] tests/test_ui/test_app_embedded_tools.py — gates: 21, flagged: 0
- [x] tests/test_ui/test_app_toolbar_overflow.py — gates: 4, flagged: 0
- [x] tests/test_ui/test_async_bridge.py — gates: 13, flagged: 0
- [x] tests/test_ui/test_dialogs.py — gates: 11, flagged: 0
- [x] tests/test_ui/test_font_manager.py — gates: 32, flagged: 6
- [x] tests/test_ui/test_graph_view.py — gates: 27, flagged: 0
- [x] tests/test_ui/test_hex_format.py — gates: 17, flagged: 0
- [x] tests/test_ui/test_hxd_panel.py — gates: 45, flagged: 0
- [x] tests/test_ui/test_icon_manager.py — gates: 33, flagged: 5
- [x] tests/test_ui/test_overflow_toolbar.py — gates: 4, flagged: 0
- [x] tests/test_ui/test_panel_dock.py — gates: 9, flagged: 0
- [x] tests/test_ui/test_process_panel.py — gates: 36, flagged: 3
- [x] tests/test_ui/test_realcov_13b_hex_calculator.py — gates: 8, flagged: 0
- [x] tests/test_ui/test_realcov_13b_hex_pattern_code_editor.py — gates: 5, flagged: 0
- [x] tests/test_ui/test_realcov_13b_hex_sections.py — gates: 8, flagged: 0
- [x] tests/test_ui/test_realcov_13b_hex_statistics.py — gates: 8, flagged: 0
- [x] tests/test_ui/test_realcov_13b_hex_widgets.py — gates: 6, flagged: 0
- [x] tests/test_ui/test_realcov_13b_hex_yara.py — gates: 3, flagged: 0
- [x] tests/test_ui/test_realcov_14b_analysis_panel.py — gates: 8, flagged: 0
- [x] tests/test_ui/test_realcov_14b_cutter_tabs.py — gates: 6, flagged: 0
- [x] tests/test_ui/test_realcov_14b_graph_view.py — gates: 6, flagged: 0
- [x] tests/test_ui/test_realcov_14b_panel_support.py — gates: 15, flagged: 0
- [x] tests/test_ui/test_realcov_14b_sandbox_report.py — gates: 6, flagged: 0
- [x] tests/test_ui/test_realcov_14b_script_manager.py — gates: 9, flagged: 0
- [x] tests/test_ui/test_realcov_15_chat_panel.py — gates: 9, flagged: 0
- [x] tests/test_ui/test_realcov_15_dialog_helpers_logging.py — gates: 2, flagged: 0
- [x] tests/test_ui/test_realcov_15_preferences_dialog.py — gates: 3, flagged: 0

## Flagged tests

### tests/test_ui/test_font_manager.py

#### `test_load_fonts_returns_bool` — LOW — N8 (existence/type-only)
- **Location:** tests/test_ui/test_font_manager.py:93
- **Current behavior:** Calls `load_fonts()` and asserts the return is a `bool`.
- **Why it is not a gate:** `load_fonts` is annotated `-> bool` and always
  returns a bool literal, so `isinstance(result, bool)` cannot fail regardless
  of whether font loading actually worked. The real outcome (True on success)
  is gated separately by `test_load_fonts_succeeds`, so this test protects
  nothing additional.
- **Recommended fix:** Delete it (redundant with `test_load_fonts_succeeds`),
  or assert the concrete value `result is True`.

#### `test_get_code_font_returns_qfont` — LOW — N4/N8 (type-only on non-None return)
- **Location:** tests/test_ui/test_font_manager.py:161
- **Current behavior:** Asserts `get_code_font()` returns a `QFont` instance.
- **Why it is not a gate:** `get_code_font` is typed `-> QFont` and constructs a
  `QFont` unconditionally; the assertion is provably-true. The meaningful
  properties (monospace, fixed pitch, size) are gated by the sibling tests
  `test_code_font_is_monospace`, `test_code_font_is_fixed_pitch`,
  `test_code_font_respects_size`.
- **Recommended fix:** Remove, or fold the type check into a behavior assertion
  (e.g. assert the family equals the resolved `code_font_family`).

#### `test_get_ui_font_returns_qfont` — LOW — N4/N8 (type-only on non-None return)
- **Location:** tests/test_ui/test_font_manager.py:226
- **Current behavior:** Asserts `get_ui_font()` returns a `QFont` instance.
- **Why it is not a gate:** Same reasoning as `get_code_font`: return type makes
  the assertion unfalsifiable; behavior is gated by `test_ui_font_is_sans_serif`
  and `test_ui_font_respects_size`.
- **Recommended fix:** Remove or assert a real property of the returned font.

#### `test_get_heading_font_returns_qfont` — LOW — N4/N8 (type-only on non-None return)
- **Location:** tests/test_ui/test_font_manager.py:281
- **Current behavior:** Asserts `get_heading_font()` returns a `QFont` instance.
- **Why it is not a gate:** Return type guarantees a `QFont`; cannot fail.
  `test_heading_font_is_bold` and `test_heading_font_respects_size` gate the
  real behavior.
- **Recommended fix:** Remove or assert a real property (bold + size).

#### `test_load_fonts_idempotent` — LOW — N4 (weak self-comparison)
- **Location:** tests/test_ui/test_font_manager.py:146
- **Current behavior:** Calls `load_fonts()` twice and asserts
  `result1 == result2`.
- **Why it is not a gate:** Two successful calls both return `True`, so the
  comparison holds; but it would *also* hold if both calls returned `False`
  (e.g. fonts broke), so it does not gate that loading actually succeeds or that
  the second call is a genuine no-op. It only proves determinism of the return,
  not idempotency of the side effects (loaded_families unchanged, no double
  registration).
- **Recommended fix:** Assert `result1 is True and result2 is True`, and that
  `loaded_families` is unchanged across the two calls (no duplicate family
  registration).

#### `test_font_config_valid_json` — LOW — N8 (type-only after parse)
- **Location:** tests/test_ui/test_font_manager.py:495
- **Current behavior:** Loads `font_config.json` and asserts it is a `dict`.
- **Why it is not a gate:** Confirms the file is parseable JSON and a dict, but
  asserts nothing about the required keys/values the application actually reads
  from it, so a config that parses but is missing every expected field passes.
- **Recommended fix:** Assert the keys the font loader consumes are present with
  expected types/values (e.g. the configured code/ui font family names).

### tests/test_ui/test_icon_manager.py

#### `test_get_icon_returns_qicon` — LOW — N8 (type-only)
- **Location:** tests/test_ui/test_icon_manager.py:136
- **Current behavior:** Asserts `get_icon("status_success")` returns a `QIcon`.
- **Why it is not a gate:** `get_icon` always returns a `QIcon` (even a null one
  on failure), so the type check cannot fail even if the icon failed to load.
  The real load is gated by `test_loads_svg_icon_successfully`
  (`not icon.isNull()`).
- **Recommended fix:** Remove, or add `assert not icon.isNull()` so a load
  failure trips it.

#### `test_missing_icon_returns_icon_object` — MEDIUM — N8 (type-only on fallback path)
- **Location:** tests/test_ui/test_icon_manager.py:446
- **Current behavior:** Calls `get_icon("nonexistent_icon_12345")` and asserts
  the result is a `QIcon`.
- **Why it is not a gate:** The named intent is the *fallback* behavior for a
  missing icon, but the assertion only checks the return type, which is `QIcon`
  on every path. A regression that makes the fallback render the wrong glyph, or
  return a non-null icon for a name with no fallback, would still pass. (The
  stronger fallback contract is gated elsewhere by
  `test_no_fallback_icon_returns_null_qicon` and
  `test_fallback_characters_are_exactly_correct`.)
- **Recommended fix:** Assert the specific expected fallback outcome for a
  missing-with-no-fallback name (null QIcon) versus a missing-with-fallback name,
  rather than only the type.

#### `test_get_icon_returns_qicon` companion `test_returns_list` — MEDIUM — N8 (type-only behavior test)
- **Location:** tests/test_ui/test_icon_manager.py:531
- **Current behavior:** `list_available_icons()` is asserted to be a `list`.
- **Why it is not a gate:** The method name claims it returns the available
  icons; asserting only `isinstance(..., list)` would pass for an empty or wrong
  list. Content is partially gated by `test_list_contains_known_icons`, so this
  one is redundant and weak.
- **Recommended fix:** Remove (covered by `test_list_contains_known_icons`), or
  assert the list equals/contains the full expected `ICON_MAP` key set.

#### `test_svg_icons_load_without_errors` — MEDIUM — N8 (type-only inside try/except)
- **Location:** tests/test_ui/test_icon_manager.py:594
- **Current behavior:** Iterates the first 20 SVG keys, calls `get_icon(name)`,
  asserts each is a `QIcon`, and `pytest.fail`s only if an exception is raised.
- **Why it is not a gate:** `get_icon` returns a `QIcon` (possibly null) without
  raising for a present-but-corrupt SVG, so a silently-broken SVG that loads to a
  null icon passes. The check is effectively "does not raise" plus a
  provably-true type assertion. The real corruption gates live in
  `TestAllMappedIconsLoad` (digest/viewBox/namespace/XML), which are strong.
- **Recommended fix:** Assert `not icon.isNull()` (or `availableSizes()` is
  non-empty) per icon, matching the pattern used in
  `test_critical_svg_icons_load_and_have_available_sizes`.

#### `test_icon_manager_available_flag` — LOW — N8 (boolean attribute snapshot)
- **Location:** tests/test_ui/test_icon_manager.py:614
- **Current behavior:** Asserts `icon_manager.icons_available` is truthy.
- **Why it is not a gate:** It asserts a single boolean flag set at construction;
  it does not exercise the detection logic against a controlled
  present/absent-assets condition, so it gates only "the flag is True in this
  environment" rather than "availability detection is correct".
- **Recommended fix:** Drive both states (assets present vs. a manager pointed at
  an empty/cleared icon set) and assert the flag flips accordingly.

### tests/test_ui/test_process_panel.py

#### `test_panel_creates` — LOW — N8 (type-only)
- **Location:** tests/test_ui/test_process_panel.py:95
- **Current behavior:** Asserts the constructed `ProcessPanel` is a `QWidget`.
- **Why it is not a gate:** `ProcessPanel` subclasses `QWidget`, so the
  `isinstance` is provably-true once construction succeeds; it degenerates to a
  "constructor does not raise" smoke check. Structure is genuinely gated by
  `test_panel_has_five_tabs`, `test_panel_tab_names`, etc.
- **Recommended fix:** Remove (subsumed by the structural tests), or assert a
  concrete construction invariant not covered elsewhere.

#### `test_import_from_package` — LOW — N8 (import-presence only)
- **Location:** tests/test_ui/test_process_panel.py:333
- **Current behavior:** Asserts `ProcessPanel is not None`.
- **Why it is not a gate:** A successfully imported module symbol is never None,
  so this only proves the import at the top of the file succeeded. The
  meaningful equivalence is gated by `test_both_imports_same_class`.
- **Recommended fix:** Remove (redundant with `test_both_imports_same_class`).

#### `test_import_from_panels` — LOW — N8 (import-presence only)
- **Location:** tests/test_ui/test_process_panel.py:337
- **Current behavior:** Asserts `ProcessPanelFromPanels is not None`.
- **Why it is not a gate:** Same as above — an imported symbol cannot be None;
  proves only that the import line ran. The cross-path identity is gated by
  `test_both_imports_same_class`.
- **Recommended fix:** Remove (redundant with `test_both_imports_same_class`).

## Acceptable skips (not flagged)

- tests/test_ui/test_realcov_13b_hex_sections.py:42 module-level
  `importorskip("intellicrack_hexcore")` — skips when the compiled Rust hexcore
  backend is absent. The thing under test is the section/strings parameter-
  forwarding logic in `sections.py`; hexcore is trusted external infrastructure,
  not the unit under test, so this is an environment/dependency skip, not a
  capability mask.
- tests/test_ui/test_realcov_13b_hex_statistics.py:32 and
  test_realcov_13b_hex_widgets.py:38 `importorskip("intellicrack_hexcore")` —
  same rationale: the hexcore document backend is a build artifact dependency.
- tests/test_ui/test_realcov_13b_hex_yara.py:31-37
  `importorskip("intellicrack.core.yara_scanner")` plus
  `pytest.skip("yara-python is not installed", allow_module_level=True)` — skips
  only when the `yara` native dependency is unavailable. yara-python is trusted
  external tooling; the rendering mixin under test is still gated when present.
- tests/test_ui/test_hxd_panel.py:120,159,172,198,212,252,319,437 and
  test_realcov_14b_panel_support.py — `pytest.skip("...Windows-only...")` /
  registry-API skips. These guard genuine OS-capability differences (winreg,
  HxD being Windows-only). On the Windows target platform the branches execute;
  the skips do not hide the capability under test on the platform where it
  applies.
- tests/test_ui/test_hxd_panel.py:264 `test_path_search_rejects_nonexistent_candidates`
  conditional skip when HxD is installed system-wide — legitimate: the PATH
  branch under test is only reachable when registry/common-dir lookups miss, and
  the test explicitly detects and documents that pre-condition; it still fires
  unconditionally on systems where HxD is absent.
- tests/test_ui/test_realcov_14b_graph_view.py:156,213 `pytest.skip` when a real
  `.text` window yields too few basic blocks / no resolvable edges — data-shape
  guards on real disassembly, not masks of the rendering logic, which is gated
  whenever the real binary produces blocks.
- tests/test_ui/test_realcov_14b_analysis_panel.py:290,312 and
  test_realcov_14b_cutter_tabs.py:185 `pytest.skip` when the resolved PE exposes
  no named imports/exports — guards against fixture variability across Windows
  builds; the rendering assertions still run on any binary that has symbols.
