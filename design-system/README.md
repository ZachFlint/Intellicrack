Intellicrack is a PyQt6 desktop application for binary analysis — a hub that
brings debuggers, disassemblers, sandboxes and AI providers into one window.
This is its design system, extracted verbatim from the application's four Qt
stylesheets (`src/intellicrack/assets/styles/*.qss`), its theme manager, font
manager and icon set. The look is a dark, VS-Code-adjacent editor skin built on
a `#007acc` accent. Build with the token names below; the values are the real
ones, not approximations.

Prefix is `--ic-`. The Qt widget names map to the `.ic-*` classes in
`components/bundle.css`, so a consumer who is not using Qt still gets the same
surface.

## Content fundamentals

- **Voice is terse and technical.** Buttons are plain verbs — `Open`, `Run`,
  `Attach`, `Approve`. The status bar and labels state a fact, never narrate.
- **Case.** Sentence case for buttons, menus and body. Headings (`ic-heading`)
  are bold, not uppercase.
- **Machine text is monospace.** Offsets, hex, disassembly, tool-call arguments,
  code and function names use `ic-font-code` (JetBrains Mono). Everything else
  uses `ic-font-ui` (Segoe UI).
- **Icons carry meaning, colour reinforces it.** Status is shown by an icon and
  a word, never colour alone (see Iconography).

## Colour

The application ships **four themes**: `dark` (the default), `light`, and the
restyled `dark2` / `light2`. Dark is the working skin; light is for bright
rooms and projection. Every token below carries all four values, so switching
theme is a token swap.

- **Surfaces stack from back to front.** `ic-window` is the window ground;
  `ic-content` is where content lives (editors, lists, tables, trees);
  `ic-chrome` is the raised furniture (menu bar, menus, toolbar, tooltips);
  `ic-header` is strips and headers (unselected tabs, table headers, panel and
  dock titles); `ic-panel` is a group-box body; `ic-field` / `ic-combo` are
  input fills. Put body text in `ic-text`, de-emphasised text in
  `ic-text-muted`, unavailable text in `ic-text-disabled`.
- **Accent is spent on one thing at a time.** `ic-accent` (`#007acc` in dark)
  marks focus borders, checked boxes, the selected-tab underline, the slider
  handle, the progress chunk and the status bar. The primary button uses the
  slightly deeper `ic-primary` with `ic-on-accent` text, hovering to
  `ic-primary-hover` and pressing to `ic-primary-pressed`. Secondary, flat,
  tool and toggle buttons stay transparent with an `ic-border` outline until
  hovered (`ic-hover`).
- **Selection is one blue.** `ic-selection` fills a selected menu / list / tree
  / table row and the text caret range; on it, text is `ic-on-selection` —
  which stays `ic-text` in the dark themes but flips to white in the light
  themes, so keep using the token rather than hardcoding a colour.
- **Status is a quartet.** `ic-success`, `ic-error`, `ic-warning`, `ic-info` for
  status text and dots; destructive controls use `ic-danger`. Tool results get
  their own tinted fills and left borders (`ic-result-success-*`,
  `ic-result-error-*`).
- **The analysis views have their own ink.** Custom-painted surfaces don't use
  the stylesheet; each reads its own colour table, and every value here comes
  from the function that actually paints:
  - disassembly and the code highlighter: `ic-asm-jump / -call / -ret / -nop /
    -register / -immediate / -memory` (ThemeManager.get_analysis_colors);
  - the hex editor and its entropy minimap: `ic-hex-*`, `ic-minimap-*`,
    `ic-entropy-low / -mid / -high` and the content-class `ic-hex-class-*`
    (hex_editor_widget.py);
  - the entropy chart and byte histogram: `ic-chart-*` (hex_editor/widgets.py);
  - the control-flow graph: `ic-cfg-*` (graph_view.py).

  All of them follow the theme *family*, so `dark2` paints with the `dark`
  values and `light2` with `light`. ThemeManager also defines hex, entropy,
  graph, minimap and selection colours that no view reads; they are left out.

Contrast, measured against WCAG 2 in all four themes. The values are the
application's own and are kept exact; where they fall short, the token's usage
note says so.

- **Holds everywhere:** body text (`ic-text`) on every surface (9:1 or better),
  `ic-text-muted` on the window and content grounds, text on `ic-selection`,
  the disassembly and code colours, and the confirm-dialog warning strip.
- **Falls short:** the user chat bubble in Dark (4.3:1) and Dark 2 (2.7:1);
  white text on the Dark 2 primary button and status bar (3.3:1); `ic-success`
  (3.9 to 4.4:1) and especially `ic-warning` (2.6:1) as text on the Light / Light
  2 window; and `ic-border-control` against `ic-field` (1.0 to 1.9:1, under the
  3:1 floor for control edges), so input fields only clearly read as fields
  once focused.
- **Painted views:** the hex editor's offset column is 4.2:1 in the dark
  family; white text on its dark selection is 3.0:1; zero bytes are dimmed to
  2.1:1 on purpose; and CFG return instructions are 3.9:1 on a dark block.
  Hex bytes, ASCII, instruction text and the disassembly colours all pass.
- Disabled text on `ic-disabled-fill` is around 2:1, which WCAG exempts for
  inactive controls.

Status always pairs a colour with an icon and a word, which keeps the weak
status colours from being the only signal. When adding UI, keep to the pairings
the usage notes name rather than relying on the failing ones.

## Typography

Two families. `ic-font-ui` is `"Segoe UI", Inter, Roboto, "Helvetica Neue",
Arial, sans-serif`; `ic-font-code` is `"JetBrains Mono", "Cascadia Code",
Consolas, "Courier New", monospace`. **JetBrains Mono ships with the app** (the
Regular and Bold files are included under `fonts/`); Segoe UI is the host UI
face.

- The stylesheet base size is **12px** (`ic-fs-12`) for every widget. Headings
  are 16px bold; dialog headers 14px; hints, search status and small print are
  11px; timestamps 10px.
- Custom-painted views size their fonts in points via `font_config.json`: the
  hex view at 11pt, code and disassembly at 10pt. The `fontSize` token family
  lists both the pixel sizes and the point sizes converted at 96 dpi.
- Weights: `ic-fw-regular` (400) for body and code, `ic-fw-semibold` (600) for
  the attach-hint, `ic-fw-bold` (700) for headings, panel titles, primary
  action buttons and tool-call headers.

## Spacing and radius

Padding and margins land on a small set of even steps: `ic-space-2` (menu-bar
padding) · 4 · 6 · 8 (the common field padding) · 10 · 12 · 16 (primary button
and tab padding) · 20 · 24. Radii: `ic-radius-xs` (2px, menu items), `-sm` (3px,
check boxes), `-md` (4px, the default for buttons / inputs / panes / group
boxes), `-lg` (6px, scroll thumbs, tool frames), `-xl` (8px, chat bubbles). The
metrics are identical across all four themes.

## Iconography

The app ships **71 flat SVG icons** in eleven families — Actions, AI, Binary,
Database, Edit, File, Help, Navigation, Security, Status, Tools — each a 24×24
glyph with a two-stop diagonal gradient and a soft drop shadow (the Status and
Tools sets are the most saturated; see the Assets section). Every icon also has
a Unicode fallback in `icon_manager.py` for when the SVG cannot load, and status
is always paired with a word. The tool icons name the integrated tools
(Ghidra, x64dbg, Frida, Cutter, GDB, OllyDbg, Cheat Engine).

An older set of **42 flat 24×24 PNG glyphs** (the Legacy asset group) is still
shipped, because ICON_MAP points 37 keys at them (document_open,
folder, ghidra_tool, refresh, settings and so on). Prefer the gradient SVG where
one exists for the same idea. Four of the PNGs are referenced nowhere in the
code: `icon_preview` and the three `status-*` PNGs.

The **brand mark** is a blue brain (`splash-icon`, the brain blue is about
`#07a2fe`) over a near-black ground (`#0d0d0d`–`#151515`); the **wordmark** sets
"Intellicrack" in white JetBrains Mono. The Logos group also holds the
**app icon** (the 256px frame of `icon.ico`) and the 1024px **splash** artwork.
The live splash screen is a separate, animated piece (see the SplashScreen
card). Use the marks as shipped; where one cannot be placed, set the name in
`ic-font-code` white on the dark ground rather than redrawing the brain.


## Consuming the previews

This system ships no JavaScript bundle; it is a class-and-token stylesheet.
`components/bundle.css` translates the Qt widget selectors into `.ic-*` classes
that read only from the `--ic-*` tokens. Load `tokens.css` then `bundle.css`,
set `data-theme` to `dark` / `light` / `dark2` / `light2`, and apply the classes.

The painted-view cards (HexEditor, EntropyChart, ControlFlowGraph) use real
data: the bytes, per-block entropy and byte counts of
`C:\Windows\System32\notepad.exe`, and five basic blocks of its CRT startup
function, laid out by the app's own CFGGraphScene. MainWindow puts the pieces
together in the real arrangement from app.py and tools.py.
