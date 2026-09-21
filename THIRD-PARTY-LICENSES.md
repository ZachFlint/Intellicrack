# Third-Party Licenses

Intellicrack is licensed GPL-3.0-or-later (see [LICENSE](LICENSE)). It relies on
third-party software that is licensed separately. This file records what those
components are, what they are licensed under, where their license texts live,
and where to obtain their source.

Verbatim license texts are vendored under [`licenses/`](licenses/).

## How Intellicrack combines with these components

This distinction decides which obligations apply, so it is stated up front.

**Aggregation.** Intellicrack drives Ghidra, radare2, rizin/Cutter, x64dbg,
QEMU, Frida and NASM as *separate processes*, over pipes, files and sockets. It
does not link against them. Under GPL-3.0 section 5 (and GPL-2.0 section 2),
placing independent programs together on a distribution medium is "mere
aggregation": each program keeps its own license, and Intellicrack's own license
is not imposed on them, nor theirs on it. This is why bundling GPL-2.0 software
such as QEMU alongside GPL-3.0-or-later Intellicrack is not a conflict.

**One genuine combined work.** `src/x64dbg-plugin` is the exception. It
`#include`s x64dbg's plugin SDK headers and links `x64dbg.lib` / `x64bridge.lib`
(see `src/x64dbg-plugin/CMakeLists.txt`). That produces a combined work with
x64dbg. x64dbg's licence is a **modified GPL-3.0** carrying an explicit
"Treatment of plugins" exception that permits plugins under other terms; the
exact modified text is vendored at
[`licenses/x64dbg/LICENSE`](licenses/x64dbg/LICENSE). Generic GPLv3 boilerplate
would misstate the terms x64dbg is actually offered under, so that file must not
be replaced with a stock copy.

## A. Redistributed in this repository

These are committed to git and therefore published with every clone.

### x64dbg plugin SDK — `tools/x64dbg/pluginsdk/`

The SDK is a build dependency: `src/x64dbg-plugin` cannot compile without it.

- **Upstream:** <https://github.com/x64dbg/x64dbg>
- **License:** GPL-3.0 **as modified by x64dbg**, including the "Treatment of
  plugins" exception — [`licenses/x64dbg/LICENSE`](licenses/x64dbg/LICENSE)
- **Exact version:** commit `85e0ff85796891ebfd3cc5bb46daedbe7ef6098c`, recorded
  in `tools/x64dbg/commithash.txt` and committed upstream 2025-08-19
- **Corresponding Source:**
  <https://github.com/x64dbg/x64dbg/tree/85e0ff85796891ebfd3cc5bb46daedbe7ef6098c>

The SDK itself bundles three further projects, whose texts are vendored:

| Component | Path in SDK | License | Text |
| --- | --- | --- | --- |
| XEDParse | `pluginsdk/XEDParse/` | LGPL-3.0 | [`licenses/x64dbg-XEDParse/LICENSE`](licenses/x64dbg-XEDParse/LICENSE) |
| jansson | `pluginsdk/jansson/` | MIT | [`licenses/jansson/LICENSE`](licenses/jansson/LICENSE) |
| lz4 | `pluginsdk/lz4/` | BSD-2-Clause (library); GPL-2.0 (programs) | [`licenses/lz4/LICENSE`](licenses/lz4/LICENSE) and [`LICENSE-lib-BSD-2-Clause`](licenses/lz4/LICENSE-lib-BSD-2-Clause) |

Only the lz4 *library* portion is used here, which is the BSD-2-Clause part.

### NASM — `tools/NASM/`

Only NASM's licence and auxiliary files are committed; `nasm.exe` is not.

- **Upstream:** <https://www.nasm.us> (<https://github.com/netwide-assembler/nasm>)
- **License:** BSD-2-Clause — already shipped at `tools/NASM/LICENSE`

## B. Redistributed by the Windows installer

`packaging/stage.ps1` copies these into `Intellicrack-Setup.exe`. They are
fetched at build time by `scripts/install-*.ps1` and are **not** committed to
this repository, but the installer redistributes them, so the obligations below
apply to every installer that is published.

| Component | Version | License | Source |
| --- | --- | --- | --- |
| x64dbg | `2025.08.19` | modified GPL-3.0 (plugin exception) | <https://github.com/x64dbg/x64dbg/releases/tag/2025.08.19> |
| Cutter | `v2.4.1` | GPL-3.0 ([text](licenses/cutter/LICENSE)) | <https://github.com/rizinorg/cutter/releases/tag/v2.4.1> |
| rizin (bundled in Cutter) | 0.8.x | LGPL-3.0 ([text](licenses/rizin/LICENSE)) | <https://github.com/rizinorg/rizin> |
| radare2 | fetched latest | mixed, mostly LGPL-3.0 ([text](licenses/radare2/LICENSE)) | <https://github.com/radareorg/radare2> |
| Ghidra | fetched latest | Apache-2.0 | <https://github.com/NationalSecurityAgency/ghidra> |
| QEMU | fetched latest | GPL-2.0 | <https://gitlab.com/qemu-project/qemu> |
| NASM | fetched latest | BSD-2-Clause | <https://github.com/netwide-assembler/nasm> |

radare2 is not uniformly LGPL-3.0: its own `COPYING.md` (vendored at
`licenses/radare2/LICENSE`) states that most of radare2 is LGPL-3.0 while
bundled plugins and dependencies carry other licenses, including GPL code in
some static builds. The shipped tree includes upstream's `licenses.r2.js`, which
emits a full per-component SBOM via `r2 -qi scripts/licenses.r2.js --`. Run it
against the staged build if an exact component-level answer is ever needed.
Upstream's Cutter Windows archive ships no license file, so the GPL-3.0 and
LGPL-3.0 texts above are vendored here and staged into the installer.

Cutter's Windows build additionally bundles Qt6 (LGPL-3.0), PySide6 (LGPL, with
a commercial option) and CPython, plus three **proprietary Microsoft
redistributables** — `d3dcompiler_47.dll`, `dxcompiler.dll` and `dxil.dll`.
Those Microsoft libraries are not open source; they are redistributed under
Microsoft's own redistribution terms and are aggregated, not linked into
Intellicrack.

## C. Vendored submodules — `vendor/`

- **Microsoft TraceEvent** (`vendor/traceevent`) — MIT, from
  `microsoft/perfview`, package 3.2.5. The MIT notice is vendored at
  [`licenses/traceevent/LICENSE`](licenses/traceevent/LICENSE). The bundled
  `Microsoft.Extensions.*` and `System.*` assemblies are MIT as well.
- **PatternLanguage** (`vendor/PatternLanguage`) — LGPL-2.1, submodule.
- **ImHex-Patterns** (`vendor/ImHex-Patterns`) — GPL-2.0-only, submodule. Its
  GPLv2 text ships in the submodule. See section E for why this is not a
  conflict.
- **community-patterns** (`vendor/community-patterns`) — GPL-2.0. A
  byte-identical second checkout of the same upstream. `packaging/stage.ps1`
  depends on this path, so it cannot be removed without also updating that
  script.

## D. Obtaining Corresponding Source

Intellicrack is distributed from network servers (GitHub, and GitHub Releases
for the installer). GPL-3.0 section 6(d) is therefore satisfied by offering
equivalent access to the Corresponding Source through the same place, and it
expressly permits that source to live on a different server provided clear
directions are given. **The tables above are those directions**: each row links
to the exact upstream tag or commit the shipped build was produced from.

No separate written offer under section 6(b) is made or required, because access
under section 6(d) is provided.

If any link above ever fails to resolve to the exact version shipped, that is a
defect — please open an issue.

## E. Open items

- **Resolved: `vendor/ImHex-Patterns` is GPL-2.0-only, and that is not a
  conflict.** Its `LICENSE` is plain GPLv2. The only "or any later version"
  wording sits at lines 296-299, inside the "How to Apply These Terms to Your
  New Programs" appendix that begins after "END OF TERMS AND CONDITIONS" — a
  template for authors, not a grant by this project. No SPDX headers appear in
  the pattern files (200 sampled) and the repository states no license in its
  README, so the conservative reading is GPL-2.0-only. That does not clash with
  Intellicrack's GPL-3.0-or-later license, because the patterns are never
  combined with it: `.hexpat` files are data interpreted at runtime by the hex
  editor, the same relationship a document has to the program that opens it.
  Shipping them alongside Intellicrack is aggregation, which GPL permits. The
  obligations are to ship the GPLv2 text (already present in the submodule) and
  not to relicense the patterns.
- **Qt6 and PySide6 texts are not separately vendored.** Both are LGPL-3.0, the
  same text already vendored at `licenses/rizin/LICENSE`, and both are named in
  section B. Upstream's Cutter archive ships neither.
- This inventory reflects the source tree, not a scan of a built installer.

---

This file is a good-faith engineering summary of the obligations stated in the
licenses named above. It is not legal advice.
