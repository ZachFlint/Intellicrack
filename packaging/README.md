# Intellicrack Installer

This directory holds everything needed to produce the offline Windows
installer for Intellicrack.

## What the installer produces

Compiling the assets in this directory yields a single, self-contained
`Intellicrack-Setup.exe` for Windows x64. Running it installs a fully working
Intellicrack on a clean machine with **zero preinstalled prerequisites** - no
system Python, no Java, no Rust toolchain, and no reverse-engineering tools
required. The bundled Python runtime, a private JDK 21, the native `hexcore`
extension, and every external tool (Ghidra, radare2, rizin/Cutter, x64dbg,
NASM, PMD, google-java-format, QEMU, and the helper utilities) all ship inside
the Setup executable. The result is a working GUI, the tool bridges, and the
QEMU sandbox backend, all offline.

The installer makes **no persistent system changes**: it writes no `PATH`,
`JAVA_HOME`, or registry environment entries. See
[Environment isolation](#environment-isolation) below.

## Installer experience

The wizard is configured for a modern, native Windows presentation:

- **System dark/light theming.** `WizardStyle=modern dynamic` makes both Setup
  and the uninstaller follow the machine's current Windows app theme
  automatically - dark on a dark machine, light on a light one - with no user
  choice required.
- **Custom wizard banner.** The welcome/finished page shows the Intellicrack
  banner (the app-icon tile composited over a brand background, currently the
  Neural Ring artwork), with a dark variant (`WizardImageFileDynamicDark`) that
  swaps in under the dark theme. `wizard/generate_banners.ps1` extracts the crisp
  256px tile straight from `icon.ico` - the single source of the wordmark - and
  composites it over the chosen background from `wizard/backgrounds/`. Every
  background is also rendered to `wizard/options/` so any can be promoted by
  changing `$SelectedKey` in the generator and re-running it.
- **GPL-3.0 license page.** Setup shows the project `LICENSE` (GPL-3.0-or-later)
  and requires acceptance before installing.
- **Native x64 only.** `ArchitecturesAllowed=x64os` restricts installation to
  native 64-bit Windows (it does not run under ARM64 x64 emulation).
- **Rich Add/Remove Programs metadata.** Publisher, version, support/update URLs,
  a description, and copyright are embedded so the entry in Apps &amp; features
  and the Setup file properties are fully populated.
- **Auto-close on install/uninstall.** `CloseApplications`/`RestartApplications`
  use the Windows Restart Manager to close a running Intellicrack before an
  in-place upgrade or uninstall and restart it afterward, avoiding
  file-in-use failures. Detection is anchored by an `AppMutex`
  (`Global\IntellicrackSingleInstance`): the running application creates that
  named mutex on startup (see
  `src/intellicrack/core/single_instance.py`), and Setup/uninstall declare the
  same name so a live instance is reliably found even across elevation.
- **Launch on finish.** The finished page offers to start Intellicrack
  (`nowait postinstall skipifsilent runasoriginaluser`), so a fresh install
  launches as the original (non-elevated) user rather than the elevated
  installer account.
- **Setup logging.** `SetupLogging=yes` writes a full install log to the user's
  temp directory for post-mortem diagnosis of a failed install.
- **Optional Hypervisor Platform enable.** When the QEMU component is selected,
  the Select Tasks page offers to enable the Windows Hypervisor Platform
  (needed for QEMU/WHPX acceleration). Setup runs DISM with the installer's
  elevation; if DISM reports exit code 3010 (feature staged, reboot required)
  the wizard requests a restart at the end.
- **Optional Defender exclusion.** A default-unchecked task adds a Microsoft
  Defender folder exclusion for the install directory, because the bundled
  activation/injection utilities can trip antivirus heuristics. Uninstall
  removes the exclusion again.
- **Clean uninstall.** `[UninstallDelete]` removes the runtime-generated
  `.intellicrack` config tree and then sweeps the whole install directory so no
  logs or `__pycache__` are orphaned. Uninstall also offers to remove the
  out-of-install tool cache at `%LOCALAPPDATA%\intellicrack_tools`; credential
  files are never touched by that prompt.

Regenerate the wizard images after changing the app icon:

```powershell
pwsh packaging\wizard\generate_banners.ps1
```

## Assets in this directory

| File | Role |
| --- | --- |
| `stage.ps1` | Assembles the fixed `build/stage` layout the installer consumes. |
| `intellicrack.iss` | Inno Setup 6 script; maps `build/stage` 1:1 onto the install directory. |
| `launcher/launcher.py` | Source of the frozen `Intellicrack.exe` launcher. |
| `launcher/launcher.spec` | PyInstaller spec that builds the launcher. |
| `ml_split.py` | Computes the ML-only distribution closure the stager moves into `ml_overlay/`. |
| `wizard/*.png` | The active wizard images (light/dark welcome banner + small page icon). |
| `wizard/backgrounds/*.png` | Brand background artwork the banner is composited over. |
| `wizard/options/*.png` | Every background rendered as a full banner, for picking the active one. |
| `wizard/generate_banners.ps1` | Regenerates the wizard images from the app icon and a chosen background. |

The staging script and the `.iss` share a fixed contract: `stage.ps1` writes
`<repo>/build/stage` and `intellicrack.iss` anchors every `[Files]` `Source:`
to `#define StageRoot "..\build\stage"`, so the staged tree maps directly onto
the chosen install directory.

## Build-machine prerequisites

These are required on the **build host**, not on the end-user machine. The
end user needs none of them.

- **pixi environment** present at `.pixi/envs/default` (the project's Python
  3.13 runtime; it becomes the bundled `runtime/`).
- **Rust toolchain + maturin** - `stage.ps1` rebuilds `hexcore` as a portable
  wheel via `pixi run maturin build --release` with
  `RUSTFLAGS=-C target-cpu=x86-64-v2`.
- **PyInstaller** (available through pixi) - builds the launcher from
  `launcher/launcher.spec`.
- **Inno Setup 6** with `iscc` on `PATH` - compiles the `.iss` into the Setup
  executable.
- **Internet access** - `stage.ps1` downloads Temurin JDK 21 from the Adoptium
  API and verifies its SHA-256 checksum.
- **Prebuilt x64dbg bridge plugin** already present under
  `tools/x64dbg/release` (the staging script asserts the `.dp64`/`.dp32`
  plugins exist; it does not build them).

The staging script fails loudly on any missing source. It also expects the
full tool trees under `tools/` (Ghidra, radare2, cutter, QEMU with its
`images/`, etc.) and the vendor pattern trees under `vendor/`.

## How to build

Run all commands from the repository root.

### 1. Stage the payload

```powershell
pwsh packaging\stage.ps1
```

This is the heavy step. It recreates `build/stage` from scratch and:

- copies the pixi env into `runtime/`, trimming dev-only and ML-only
  distributions;
- rebuilds the portable `hexcore` wheel and installs it into the runtime;
- materializes `app/src/intellicrack`;
- moves the ML-only distributions (torch, transformers, and their exclusive
  dependencies) into a separate `ml_overlay/`;
- copies the multi-GB tool trees (Ghidra, radare2, Cutter, x64dbg, QEMU,
  NASM, PMD, google-java-format, and the helper utilities);
- downloads and checksum-verifies Temurin JDK 21 under the Ghidra tree;
- copies the vendor pattern trees and the standalone `hexbench` GUI;
- stages the optional bundled Debian sandbox guest image; and
- builds the `Intellicrack.exe` launcher with PyInstaller.

A missing source is a hard failure, never a silent skip.

### 2. Verify the stage

```powershell
pixi run pytest tests\packaging\test_stage_matches_iss.py
```

This test confirms `build/stage` contains every required binary and that the
`.iss` `Source:` entries map back onto the staged tree.

### 3. Compile the installer

```powershell
iscc packaging\intellicrack.iss
```

This produces `Intellicrack-Setup.exe` (base name `Intellicrack-Setup`, from
`OutputBaseFilename` in the `.iss`).

## Components

The core platform is required; every external tool and every optional stack is
its own component. Everything is baked into the offline Setup executable - the
checkboxes only decide what lands on disk, never whether a download occurs.

**Required**

- `core` - the Intellicrack platform, the bundled Python runtime, the
  application source, and the vendor data. Always installed.

**Optional external tools** (default-checked in the Full install type; uncheck
to bring your own - see below)

- `tool_ghidra` - Ghidra 11.4.2 plus the private, self-contained JDK 21 (the
  JDK rides this component).
- `tool_radare2` - radare2 framework.
- `tool_rizin` - Cutter / rizin toolkit.
- `tool_x64dbg` - x64dbg with the Intellicrack bridge plugins.
- `tool_nasm` - NASM assembler.
- `tool_pmd` - PMD source analyzer.
- `tool_gjf` - google-java-format.
- `tool_adobeinjector` - Adobe injector helper.
- `tool_idmactivator` - IDM activator helper.
- `tool_windowspatch` - Windows activation helper.

**Optional stacks**

- `ml` - the local ML inference stack (torch + transformers); multi-GB. Its
  files merge into `runtime/Lib/site-packages` at install time. When selected,
  the installer warns (does not block) if the target drive has under ~12 GB
  free.
- `hexbench` - the standalone Hexbench hex GUI, which runs the `hexcore`
  runtime in a separate process, independent of the main app.
- `qemu` - the bundled QEMU sandbox backend. The final installer page offers
  an optional, unchecked step to enable the Windows Hypervisor Platform
  feature (needed for QEMU/WHPX acceleration).
- `qemu\debianguest` - the ready-to-run Debian sandbox guest image (~800 MB).

## Bring-your-own tool

Unchecking a tool component means Intellicrack ships without that tool on
disk. Point Intellicrack at your own install via
**Tools -> Tool Settings -> Browse** to the executable. rizin and radare2 also
resolve from `PATH` when present.

## Environment isolation

The installer makes **no** persistent `PATH`, `JAVA_HOME`, or registry
environment changes. All environment wiring happens at runtime, inside the
child process the launcher spawns:

- The frozen `Intellicrack.exe` launcher resolves the install directory from
  its own location.
- It builds an ephemeral environment - a copy of the current process
  environment - with the bundled runtime and tool directories prepended to
  `PATH`, `PYTHONPATH` pointed at `app/src`, and `JAVA_HOME` set to the private
  bundled JDK when the Ghidra component is present.
- It launches `runtime\pythonw.exe -m intellicrack` with that environment and
  does not touch the machine or user environment.

Only directories that actually exist are added, so a tool component the user
did not install never shadows a bring-your-own configuration.

## Runtime layout on the target

```
<installdir>\Intellicrack.exe     the frozen launcher
<installdir>\runtime\             the bundled Python 3.13 environment
<installdir>\app\src\             the application source (intellicrack package)
<installdir>\app\tools\           the installed external tool components
<installdir>\app\vendor\          the vendor pattern / data trees
<installdir>\hexbench\            optional standalone Hexbench GUI
<installdir>\qemu-guest\          optional bundled Debian sandbox guest image
```

## Caveats

- **Minimum CPU: x86-64-v2.** The bundled native `hexcore` runtime is compiled
  for the x86-64-v2 microarchitecture level (SSE4.2 + POPCNT, roughly Intel
  Nehalem / AMD Bulldozer and newer). Older processors cannot load it. Setup
  surfaces this note and refuses non-64-bit or pre-Windows-10 systems.
- **Debian sandbox guest.** The bundled Debian guest must have
  `qemu-guest-agent` installed in-guest to be usable by the sandbox.
- **Windows sandbox guests are user-provided.** For licensing reasons no
  Windows guest image is bundled; supply your own and select it through the
  Sandbox Settings dialog (`qemu_image_path`).
- **ML is a multi-GB optional component.** Skip it unless you need local
  inference; it can be installed later by re-running Setup.
- **Antivirus.** The bundled cracking/activation utilities may trip antivirus
  heuristics on the final Setup executable.
