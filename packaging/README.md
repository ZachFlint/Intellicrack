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
NASM, and QEMU) all ship inside
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
- **Custom wizard banner, per theme.** The welcome/finished page shows the
  Intellicrack banner. `WizardImageFile` (`banner-light.png`) is a genuinely
  light render - the app-icon tile on a soft light gradient with a dark subtitle -
  and `WizardImageFileDynamicDark` (`banner-dark.png`) is the app-icon tile
  composited over a dark brand background (currently the Neural Ring artwork);
  Setup swaps to the dark one under the dark theme, so the two are distinct
  images rather than the same file. `wizard/generate_banners.ps1` extracts the
  crisp 256px tile straight from `icon.ico` - the single source of the wordmark -
  and renders both variants plus the small page icon. Every dark background is
  also rendered to `wizard/options/` so any can be promoted by changing
  `$SelectedKey` in the generator and re-running it. `wizard/generate_icon.ps1`
  rebuilds `icon.ico` itself with a full 16-256px frame set.
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
  the Select Tasks page offers - **default-unchecked** - to enable the Windows
  Hypervisor Platform (needed for QEMU/WHPX acceleration). Setup runs DISM
  through `ExecAndLogOutput` behind a progress page: that call hands the child
  process output to the script line by line (plain `Exec` pumps the message
  queue just as well, but discards the output), so every DISM line is written to
  the Setup log and the progress bar advances as DISM works instead of sitting
  at 0% for the whole minute-plus enable. Exit code 3010 (feature staged, reboot
  required) requests a restart at the end, and any other non-zero DISM result is
  surfaced to the user rather than silently logged.
- **Optional Defender exclusion.** A default-unchecked task adds a Microsoft
  Defender folder exclusion for the install directory **before** the bundled
  activation/injection utilities are extracted (at `ssInstall`), so they never
  land on disk unexcluded. A failure to apply it is surfaced to the user;
  uninstall removes the exclusion again.
- **Per-user writable state.** The launcher points the application at a per-user
  state directory under `%LOCALAPPDATA%\Intellicrack` (via `INTELLICRACK_STATE_DIR`),
  so credentials (`.env`), config, logs, and data are written there rather than
  under the read-only, world-readable install directory - and survive uninstall.
- **Startup diagnostics.** `Intellicrack.exe` is windowed, so a fatal startup
  failure (missing runtime, spawn error) is shown in a message box rather than
  written to a `sys.stderr` that does not exist in a windowed process.
- **Upgrade-safe installs.** `[InstallDelete]` clears the install-managed trees
  (runtime, app source/tools/vendor, hexbench, guest image) before files are
  copied, so an upgrade never leaves stale files shadowing new ones on
  `PYTHONPATH`, and deselecting a component (e.g. the multi-GB ML overlay)
  actually removes it. `SolidCompression=no` keeps a Compact/custom install from
  decompressing the whole archive just to skip components.
- **Clean uninstall.** `[UninstallDelete]` removes the runtime-generated
  `.intellicrack` config tree and then sweeps the whole install directory so no
  logs or `__pycache__` are orphaned. Uninstall also offers to remove the
  out-of-install tool cache at `%LOCALAPPDATA%\intellicrack_tools`; credential
  and config files (under `%LOCALAPPDATA%\Intellicrack`) are never touched.
- **Unattended-safe.** No script-raised dialog can stall a `/SILENT` or
  `/VERYSILENT` run. The advisory prompts are already gated on `WizardSilent`,
  and the two that must still speak under an unattended run - the fatal
  Windows-version refusal and the uninstaller's tool-cache question - use
  `SuppressibleMsgBox`, because a plain `MsgBox` is one of the message boxes
  Inno cannot suppress even with `/SUPPRESSMSGBOXES`. The tool-cache prompt
  defaults to **no** when suppressed, so an unattended uninstall leaves
  `%LOCALAPPDATA%\intellicrack_tools` in place rather than destroying it without
  being asked. `SetupMutex` separately stops two Setup processes from racing on
  the same install tree - something `AppMutex`, which only detects a running
  *application*, does not cover.
- **Optional code signing.** `SignTool`/`SignedUninstaller=yes` are emitted only
  when the `SignToolName` preprocessor symbol is defined at compile time, so the
  Setup executable and the generated uninstaller are signed on a release build
  and an unsigned local build still compiles unchanged. See
  [Compile the installer](#3-compile-the-installer).
- **Provenance stamp.** `app\build-info.json` (commit, short SHA, dirty flag,
  version, UTC build time), written by `stage.ps1`, ships with the `core`
  component, so an installed tree names the exact commit it was built from.

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
| `launcher/hexbench_launcher.py` | Source of the frozen `Hexbench.exe` launcher. |
| `launcher/hexbench_launcher.spec` | PyInstaller spec that builds the Hexbench launcher. |
| `ml_split.py` | Computes the ML-only distribution closure the stager moves into `ml_overlay/`. |
| `jdk21.lock.json` | Pins the exact Temurin JDK 21 asset URL and SHA-256; the in-repo trust anchor `stage.ps1` verifies the download against. |
| `version.generated.iss` | Version defines (`AppVersion`/`AppVerNumeric`) that `stage.ps1` regenerates from `_metadata.py` and `intellicrack.iss` `#include`s. |
| `wizard/*.png` | The active wizard images (distinct light/dark welcome banners + small page icon). |
| `wizard/backgrounds/*.png` | Brand background artwork the dark banner is composited over. |
| `wizard/options/*.png` | Every dark background rendered as a full banner, for picking the active one. |
| `wizard/generate_banners.ps1` | Regenerates the wizard images (light + dark banners, small icon) from the app icon. |
| `wizard/generate_icon.ps1` | Rebuilds `icon.ico` with a full 16-256px frame set from the 256px source. |

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
- **PyInstaller** (available through pixi) - builds the two launchers from
  `launcher/launcher.spec` and `launcher/hexbench_launcher.spec`.
- **Inno Setup 6.6.0 or newer** with `iscc` on `PATH` - compiles the `.iss` into
  the Setup executable. 6.6.0 is a hard floor, not a preference: the script uses
  the dynamic wizard appearance (`WizardStyle=modern dynamic`) and the
  theme-specific `WizardImageFileDynamicDark` banner, both introduced in 6.6.0,
  on top of `ArchitecturesAllowed=x64os` from 6.3.0. `intellicrack.iss` checks
  the compiler version with an ISPP `#if VER < EncodeVer(6, 6, 0)` guard and
  fails with that message rather than with a confusing unknown-directive error.
- **A code-signing certificate** - *optional*. Only needed to produce a signed
  Setup executable and uninstaller; see
  [Compile the installer](#3-compile-the-installer).
- **Internet access** - `stage.ps1` downloads the exact Temurin JDK 21 asset
  pinned in `jdk21.lock.json` (with bounded retry) and refuses to proceed unless
  its SHA-256 matches the in-repo pin.
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
  NASM);
- downloads and checksum-verifies Temurin JDK 21 under the Ghidra tree;
- copies the vendor pattern trees and the standalone `hexbench` GUI;
- stages the optional bundled Debian sandbox guest image; and
- builds the `Intellicrack.exe` and `Hexbench.exe` launchers with PyInstaller.

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
`OutputBaseFilename` in the `.iss`). Compiled this way the Setup executable and
the uninstaller are **unsigned** - which is fine for a local build.

#### Signed builds

Inno signs through a *named* Sign Tool: the `.iss` references the name, and the
name is bound to an actual command line on the `iscc` command line. Signing is
therefore opt-in, mirroring the `INTELLICRACK_SIGN_PFX` launcher signing in
`stage.ps1`: `intellicrack.iss` emits `SignTool` and `SignedUninstaller=yes`
only inside `#ifdef SignToolName`, so both halves must be supplied together.

```powershell
$sign = 'signtool.exe sign /fd SHA256 /f $qC:\certs\intellicrack.pfx$q ' +
        '/p $qPFX_PASSWORD$q /tr http://timestamp.digicert.com /td SHA256 $f'
iscc /DSignToolName=intellicrack "/Sintellicrack=$sign" packaging\intellicrack.iss
```

- `/DSignToolName=intellicrack` defines the preprocessor symbol, which turns on
  the `SignTool=` and `SignedUninstaller=yes` directives.
- `/Sintellicrack=<command>` binds that same name to the command. `$f` (the file
  to sign, required) and `$q` (a quote) are Inno's substitutions, not shell
  syntax - build the command in **single**-quoted PowerShell strings so they
  reach `iscc` literally instead of being expanded as PowerShell variables.
- With `SignedUninstaller=yes` the uninstaller is signed on the fly by the same
  tool, so no manual signing round-trip is needed.
- Defining `SignToolName` without a matching `/S<name>=` is a compile error, and
  the reverse (a `/S` with no `/D`) simply produces an unsigned build.

Signing the launchers inside the payload is a separate, independent step handled
by `stage.ps1` via `INTELLICRACK_SIGN_PFX` / `INTELLICRACK_SIGN_PASS` /
`INTELLICRACK_SIGN_TS`; set both if you want the launchers *and* the installer
signed.

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

`Hexbench.exe` is the same idea for the optional hex editor, with two
differences that matter. It puts the install directory itself on `PYTHONPATH`
and runs `runtime\python.exe -m hexbench`, because the editor resolves its
`static` tree relative to its own `__file__` and so must be imported as a module
of the staged package. And it spawns that child under `CREATE_NO_WINDOW` rather
than from `pythonw.exe`: hexbench writes diagnostics to `sys.stderr`
unconditionally, and a windowless interpreter leaves that stream as `None`,
which would turn the first diagnostic into an `AttributeError`. The editor is
deliberately not frozen by `src/hexbench/hexbench.spec` for the installer --
that spec is for standalone distribution and would embed a second interpreter,
webview and hexcore next to the ones `runtime\` already provides.

## Runtime layout on the target

```
<installdir>\Intellicrack.exe     the frozen launcher
<installdir>\Hexbench.exe         the frozen Hexbench launcher (hexbench component)
<installdir>\runtime\             the bundled Python 3.13 environment
<installdir>\app\build-info.json  the commit/version stamp of this build
<installdir>\app\src\             the application source (intellicrack package)
<installdir>\app\tools\           the installed external tool components
<installdir>\app\vendor\          the vendor pattern / data trees
<installdir>\hexbench\            optional Hexbench GUI (package source)
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
