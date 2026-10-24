# Intellicrack Commands
# Configure shell for Windows

set unstable
[windows]
set shell := ["pwsh.exe", "-NoLogo", "-NoProfile", "-Command"]

pixi := "pixi run"
src := "src/intellicrack"
src_and_tests := "src/intellicrack/ tests/"
mdlint2 := "node node_modules/markdownlint-cli2/markdownlint-cli2-bin.mjs"

# Every recipe accepts --help / -h, which prints concise usage (derived from
# this justfile's own metadata by scripts/recipe-help.ps1) and runs nothing
# else. Recipes that take arguments detect --help/-h inside those arguments;
# zero-argument recipes declare [arg('help', ...)] so just parses the flag.
# Work that used to live in a dependency is inlined into the else branch so
# that --help never triggers a build, a clean, or a setup step.
#
# The heavy / multi-step recipes run their real work through
# scripts/run-logged.ps1, which streams every line (ours and the underlying
# tools') to the console and, with a timestamp and ANSI stripped, into a single
# rolling logs/justfile.log -- newest run on top, capped at 30000 lines. That
# wrapper also forces debug-level verbosity across the child process tree
# (RUST_LOG, CARGO_TERM_VERBOSE, PYTEST_ADDOPTS, CMAKE_VERBOSE_MAKEFILE,
# BUILDKIT_PROGRESS, PIP_VERBOSE); tools a recipe calls directly get their own
# debug flag at the call site. The `; exit $LASTEXITCODE` after each wrapped
# call propagates the real exit code, because a script file's exit only sets
# $LASTEXITCODE in the caller.

# build-hexbench runs afterwards, since it needs the environment this installs
[arg('help', long='help', short='h', value='true')]
[doc('Complete installation with all post-install tasks, then build Hexbench')]
[group('install')]
install help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install } else { & scripts/run-logged.ps1 -Recipe install -Body { & scripts/install-all.ps1; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & '{{ just_executable() }}' --justfile '{{ justfile() }}' build-hexbench }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Install Node.js dev-tooling dependencies (markdownlint-cli2, jsonlint) via yarn')]
[group('install')]
install-yarn help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install-yarn } else { & scripts/run-logged.ps1 -Recipe install-yarn -Body { yarn install }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Update everything: pixi env, cargo crate (hexcore), yarn deps')]
[group('update')]
update help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe update } else { & scripts/run-logged.ps1 -Recipe update -Body { Write-Host '==> pixi upgrade' -ForegroundColor Cyan; pixi upgrade; Write-Host '==> cargo (hexcore)' -ForegroundColor Cyan; Push-Location 'src/intellicrack-hexcore'; cargo upgrade --incompatible --pinned -vv; cargo update --recursive -vv; cargo fetch -vv; Pop-Location; Write-Host '==> hexbench dependencies' -ForegroundColor Cyan; & src/hexbench/update-deps.ps1; Write-Host '==> yarn up' -ForegroundColor Cyan; yarn up '*'; Write-Host '==> yarn dedupe' -ForegroundColor Cyan; yarn dedupe; Write-Host '==> Update complete' -ForegroundColor Green }; exit $LASTEXITCODE }

# Remove pixi environment
[arg('help', long='help', short='h', value='true')]
[group('install')]
uninstall help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe uninstall } else { & scripts/run-logged.ps1 -Recipe uninstall -Body { & scripts/uninstall.ps1 }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Download and install the latest Ghidra reverse engineering tool')]
[group('install')]
install-ghidra help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install-ghidra } else { & scripts/run-logged.ps1 -Recipe install-ghidra -Body { & scripts/install-ghidra.ps1 }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Download and install the latest radare2 reverse engineering framework')]
[group('install')]
install-radare2 help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install-radare2 } else { & scripts/run-logged.ps1 -Recipe install-radare2 -Body { & scripts/install-radare2.ps1 }; exit $LASTEXITCODE }

# hexcore goes first because hexbench and intellicrack bundle it; the installer goes after the
# x64dbg plugin because stage.ps1 copies the plugin out of tools/x64dbg.
[arg('all', long='all', value='true')]
[arg('help', long='help', short='h', value='true')]
[doc('Build hexcore, the x64dbg plugin, Hexbench and Intellicrack; --all adds the installer and test sandbox')]
[group('build')]
build all='false' help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe build } else { & scripts/run-logged.ps1 -Recipe build -RecipeArgs '{{ all }}' -Body { $steps = @('build-hexcore', 'build-x64dbg-plugin', 'build-hexbench', 'build-intellicrack'); if ('{{ all }}' -eq 'true') { $steps += @('build-installer', 'build-testing-sandbox') }; foreach ($step in $steps) { Write-Host "==> just $step" -ForegroundColor Cyan; & '{{ just_executable() }}' --justfile '{{ justfile() }}' $step; if ($LASTEXITCODE -ne 0) { Write-Host "==> $step failed (exit $LASTEXITCODE)" -ForegroundColor Red; exit $LASTEXITCODE } }; Write-Host "==> build complete: $($steps -join ', ')" -ForegroundColor Green }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Build the Rust hex editor core (intellicrack-hexcore) tuned for meteorlake')]
[group('build')]
build-hexcore help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe build-hexcore } else { & scripts/run-logged.ps1 -Recipe build-hexcore -Body { $env:RUSTFLAGS = '-C target-cpu=meteorlake'; cd src/intellicrack-hexcore && {{ pixi }} maturin develop --release -v }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Build the standalone Hexbench hex editor executable (PyInstaller onefile)')]
[group('build')]
build-hexbench help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe build-hexbench } else { & scripts/run-logged.ps1 -Recipe build-hexbench -Body { if (-not (Test-Path 'src/hexbench/hexbench.spec')) { Write-Host 'src/hexbench is missing, so Hexbench cannot be built' -ForegroundColor Red; exit 1 }; {{ pixi }} pyinstaller --log-level DEBUG --noconfirm --distpath dist/hexbench --workpath build/hexbench src/hexbench/hexbench.spec; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; Write-Host "==> dist/hexbench/Hexbench.exe" -ForegroundColor Green; $exe = (Resolve-Path 'dist/hexbench/Hexbench.exe').ProviderPath; $link = Join-Path (Get-Location).ProviderPath 'Hexbench.lnk'; $shell = New-Object -ComObject WScript.Shell; $sc = $shell.CreateShortcut($link); $sc.TargetPath = $exe; $sc.WorkingDirectory = Split-Path -Parent $exe; $sc.IconLocation = "$exe,0"; $sc.Description = 'Hexbench standalone hex editor'; $sc.Save(); Write-Host "==> $link" -ForegroundColor Green }; exit $LASTEXITCODE }

# Set INTELLICRACK_ONEFILE=1 for a single self-extracting exe, or INTELLICRACK_LEAN=1 to drop torch/transformers.
[arg('help', long='help', short='h', value='true')]
[doc('Build the full Intellicrack platform executable (PyInstaller, folder build by default)')]
[group('build')]
build-intellicrack help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe build-intellicrack } else { & scripts/run-logged.ps1 -Recipe build-intellicrack -Body { if (-not (Test-Path 'Intellicrack.spec')) { Write-Host 'Intellicrack.spec is missing, so Intellicrack cannot be built' -ForegroundColor Red; exit 1 }; {{ pixi }} pyinstaller --log-level DEBUG --noconfirm --distpath dist/intellicrack --workpath build/intellicrack Intellicrack.spec; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; $folder = 'dist/intellicrack/Intellicrack/Intellicrack.exe'; $single = 'dist/intellicrack/Intellicrack.exe'; $exe = if (Test-Path $folder) { $folder } elseif (Test-Path $single) { $single } else { Write-Host 'Build produced no Intellicrack.exe' -ForegroundColor Red; exit 1 }; Write-Host "==> $exe" -ForegroundColor Green }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Build x64dbg bridge plugin from source and deploy to x64dbg plugins directory')]
[group('build')]
build-x64dbg-plugin help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe build-x64dbg-plugin } else { & scripts/run-logged.ps1 -Recipe build-x64dbg-plugin -Body { & scripts/install-x64dbg-plugin.ps1 }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Delete x64dbg bridge plugin build artifacts (build*/ trees and bin/ binaries)')]
[group('build')]
clean-x64dbg-plugin help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe clean-x64dbg-plugin } else { & scripts/run-logged.ps1 -Recipe clean-x64dbg-plugin -Body { $dirs = @(Get-ChildItem 'src/x64dbg-plugin' -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'build*' -or $_.Name -eq 'bin' }); if (-not $dirs) { Write-Host '==> already clean: no build*/ or bin/ under src/x64dbg-plugin' -ForegroundColor DarkGray } else { foreach ($d in $dirs) { $mb = [math]::Round((Get-ChildItem $d.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB, 1); Remove-Item $d.FullName -Recurse -Force; Write-Host "==> removed src/x64dbg-plugin/$($d.Name) ($mb MB)" -ForegroundColor Green } } }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Run the Hexbench quality gates (lint, types, docstrings, tests)')]
[group('test')]
test-hexbench help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe test-hexbench } else { & scripts/run-logged.ps1 -Recipe test-hexbench -Body { & src/hexbench/gate.ps1 }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Run Rust hex editor core tests')]
[group('test')]
test-hexcore help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe test-hexcore } else { & scripts/run-logged.ps1 -Recipe test-hexcore -Body { cd src/intellicrack-hexcore && {{ pixi }} cargo test }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Clean Rust hex editor core build artifacts')]
[group('build')]
clean-hexcore help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe clean-hexcore } else { & scripts/run-logged.ps1 -Recipe clean-hexcore -Body { cd src/intellicrack-hexcore && {{ pixi }} cargo clean }; exit $LASTEXITCODE }

# Stage flags for build-installer's dependency invocation; empty means a full stage.
STAGE_ARGS := ""

# The heavy step: recreates build/stage from scratch (runtime, tools, JDK, launchers).
# Flags are forwarded to stage.ps1, e.g. -SkipJdkDownload -SkipGuestImage -SkipSigning.
[doc('Stage the installer payload into build/stage (packaging/stage.ps1)')]
[group('installer')]
stage-installer *ARGS:
    @if (('{{ ARGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe stage-installer } else { & scripts/run-logged.ps1 -Recipe stage-installer -RecipeArgs '{{ ARGS }}' -Body { if (-not (Test-Path 'packaging/stage.ps1')) { Write-Host 'packaging/stage.ps1 is missing, so the payload cannot be staged' -ForegroundColor Red; exit 1 }; pwsh -NoLogo -NonInteractive -File packaging/stage.ps1 {{ ARGS }}; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; Write-Host "==> build/stage" -ForegroundColor Green }; exit $LASTEXITCODE }

# Stages the payload, then compiles it with Inno Setup. scripts/build-installer.ps1
# drives both steps and captures their combined output in logs/installer/build.log
# (rolling: each build replaces the previous). It runs no tests -- verify the staged
# tree separately with `just test module --module tests/packaging` when you want it.
# ARGS reach iscc, e.g. just build-installer /DSignToolName=intellicrack.
# Stage flags come from the STAGE_ARGS variable, since they go to a different tool:
# just STAGE_ARGS='-SkipJdkDownload -SkipGuestImage' build-installer
[doc('Build the Setup executable: stage, then compile with Inno Setup')]
[group('installer')]
build-installer *ARGS:
    @if (('{{ ARGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe build-installer } else { & scripts/run-logged.ps1 -Recipe build-installer -RecipeArgs '{{ ARGS }}' -Body { & scripts/build-installer.ps1 -StageArgs "{{ STAGE_ARGS }}" -IsccArgs "{{ ARGS }}" }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Delete installer build artifacts (build/ and packaging/Output/)')]
[group('installer')]
clean-installer help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe clean-installer } else { & scripts/run-logged.ps1 -Recipe clean-installer -Body { & '{{ just_executable() }}' --justfile '{{ justfile() }}' _remove-paths 'build' 'packaging/Output' }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Delete Hexbench build artifacts (dist/hexbench, build/hexbench, Hexbench.lnk)')]
[group('build')]
clean-hexbench help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe clean-hexbench } else { & scripts/run-logged.ps1 -Recipe clean-hexbench -Body { & '{{ just_executable() }}' --justfile '{{ justfile() }}' _remove-paths 'dist/hexbench' 'build/hexbench' 'Hexbench.lnk' }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Delete Intellicrack build artifacts (dist/intellicrack, build/intellicrack)')]
[group('build')]
clean-intellicrack help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe clean-intellicrack } else { & scripts/run-logged.ps1 -Recipe clean-intellicrack -Body { & '{{ just_executable() }}' --justfile '{{ justfile() }}' _remove-paths 'dist/intellicrack' 'build/intellicrack' }; exit $LASTEXITCODE }

[private]
_remove-paths +PATHS:
    @foreach ($p in '{{ PATHS }}'.Split(' ')) { if (Test-Path $p) { $mb = [math]::Round((Get-ChildItem $p -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB, 1); Remove-Item $p -Recurse -Force; Write-Host "==> removed $p ($mb MB)" -ForegroundColor Green } else { Write-Host "==> already absent: $p" -ForegroundColor DarkGray } }

[arg('help', long='help', short='h', value='true')]
[doc('Download and install the latest QEMU emulator')]
[group('install')]
install-qemu help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install-qemu } else { & scripts/run-logged.ps1 -Recipe install-qemu -Body { & scripts/install-qemu.ps1 }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Download and install the latest x64dbg debugger')]
[group('install')]
install-x64dbg help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install-x64dbg } else { & scripts/run-logged.ps1 -Recipe install-x64dbg -Body { & scripts/install-x64dbg.ps1 }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Download and install the latest Cutter reverse engineering tool')]
[group('install')]
install-cutter help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install-cutter } else { & scripts/run-logged.ps1 -Recipe install-cutter -Body { & scripts/install-cutter.ps1 }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Download the latest Inno Setup and portable-install it into tools/innosetup (installer compiler)')]
[group('install')]
install-inno help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install-inno } else { & scripts/run-logged.ps1 -Recipe install-inno -Body { & scripts/install-inno.ps1 }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Clean Python bytecode and test/lint caches')]
[group('cleanup')]
clean-caches help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe clean-caches } else { & scripts/run-logged.ps1 -Recipe clean-caches -Body { & scripts/clean.ps1 -Pixi "{{ pixi }}" -SrcAndTests "{{ src_and_tests }}" }; exit $LASTEXITCODE }

# --all is opt-in because clean-testing-sandbox deletes the sandbox image, a multi-hour rebuild.
[arg('all', long='all', value='true')]
[arg('help', long='help', short='h', value='true')]
[doc('Clean caches and hexcore, x64dbg plugin, Hexbench and Intellicrack artifacts; --all adds the installer and test sandbox')]
[group('cleanup')]
clean all='false' help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe clean } else { & scripts/run-logged.ps1 -Recipe clean -RecipeArgs '{{ all }}' -Body { $steps = @('clean-caches', 'clean-hexcore', 'clean-x64dbg-plugin', 'clean-hexbench', 'clean-intellicrack'); if ('{{ all }}' -eq 'true') { $steps += @('clean-installer', 'clean-testing-sandbox') }; foreach ($step in $steps) { Write-Host "==> just $step" -ForegroundColor Cyan; & '{{ just_executable() }}' --justfile '{{ justfile() }}' $step; if ($LASTEXITCODE -ne 0) { Write-Host "==> $step failed (exit $LASTEXITCODE)" -ForegroundColor Red; exit $LASTEXITCODE } }; Write-Host "==> clean complete: $($steps -join ', ')" -ForegroundColor Green }; exit $LASTEXITCODE }

# Run tests in Docker sandbox. Usage: just test [TYPE] [FLAGS...]
# TYPE: unit (default), all, integration, e2e, smoke, parallel, failed, verbose, bench, module, module-cov, registry, custom
# FLAGS: --module NAME, --extra-args "...", --rebuild, --rw, --network NAME, --memory X, --cpus X, --log-level LEVEL

# Examples: just test | just test module --module bridges | just test custom --extra-args "-x tests/test_core"
[group('test')]
test *ARGS='unit':
    @if (('{{ ARGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe test } else { & scripts/run-logged.ps1 -Recipe test -RecipeArgs '{{ ARGS }}' -Body { & '{{ just_executable() }}' --justfile '{{ justfile() }}' fix-pyqt6-icu; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; {{ pixi }} python -m scripts.sandbox.docker_sandbox {{ ARGS }}; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; {{ pixi }} python -m scripts.host_native_tests }; exit $LASTEXITCODE }

# Run only the host-native pass (Intel XPU, local Ollama, debug symbols, raw disk, loopback) natively on the host.
# Usage: just test-host [extra pytest args...]
[group('test')]
test-host *ARGS:
    @if (('{{ ARGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe test-host } else { & scripts/run-logged.ps1 -Recipe test-host -RecipeArgs '{{ ARGS }}' -Body { & '{{ just_executable() }}' --justfile '{{ justfile() }}' fix-pyqt6-icu; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; {{ pixi }} python -m scripts.host_native_tests {{ ARGS }} }; exit $LASTEXITCODE }

# Measure test coverage. Default runs both; scope with --python (sandbox suite, 95% gate) or --rust (cargo llvm-cov).
# Extra flags require exactly one target, e.g. just test-coverage --python --memory 16g | just test-coverage --rust --html
[group('test')]
test-coverage *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe test-coverage } else { & scripts/run-logged.ps1 -Recipe test-coverage -RecipeArgs '{{ FLAGS }}' -Body { & scripts/test-coverage.ps1 -Pixi "{{ pixi }}" {{ FLAGS }} }; exit $LASTEXITCODE }

# Open an interactive shell inside the Docker sandbox (add --rw for writable workspace)
[group('sandbox')]
sandbox *ARGS:
    @if (('{{ ARGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe sandbox } else { {{ pixi }} python -m scripts.sandbox.docker_sandbox --shell {{ ARGS }} }

# Build or refresh the Intellicrack Docker sandbox image
[group('sandbox')]
build-testing-sandbox *ARGS:
    @if (('{{ ARGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe build-testing-sandbox } else { & scripts/run-logged.ps1 -Recipe build-testing-sandbox -RecipeArgs '{{ ARGS }}' -Body { $env:DOCKER_BUILDKIT='0'; {{ pixi }} python -m scripts.sandbox.docker_sandbox --rebuild --build-only {{ ARGS }} }; exit $LASTEXITCODE }

# Remove cached Intellicrack Docker sandbox images
[arg('help', long='help', short='h', value='true')]
[group('sandbox')]
clean-testing-sandbox help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe clean-testing-sandbox } else { & scripts/run-logged.ps1 -Recipe clean-testing-sandbox -Body { docker image prune -af --filter "label=intellicrack-sandbox=1" }; exit $LASTEXITCODE }

# Verify no mocks or fake data
[arg('help', long='help', short='h', value='true')]
[group('test')]
test-verify-real help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe test-verify-real } else { & scripts/test-verify-real.ps1 -Pixi "{{ pixi }}" }

# Lint code with ruff
[group('lint')]
lint *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe lint } else { & scripts/lint-check.ps1 -Pixi "{{ pixi }}" -Src "{{ src }}" -Flags "{{ FLAGS }}" }

# Fix linting issues automatically
[group('lint')]
lint-fix *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe lint-fix } else { & scripts/lint-fix.ps1 -Pixi "{{ pixi }}" -Src "{{ src }}" -Flags "{{ FLAGS }}" }

# Inspect code with Qodana locally, writing reports to reports/qodana
[group('lint')]
qodana *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe qodana } else { & scripts/run-qodana.ps1 -Flags "{{ FLAGS }}" }

# Find dead code, secrets, and risky flows with skylos
[group('lint')]
skylos *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe skylos } else { & scripts/run-lint-tool.ps1 -ToolName skylos -DisplayName Skylos -Command "{{ pixi }} skylos {{ FLAGS }} --json --no-upload --no-grep-verify --no-provenance {{ src }}" -Pixi "{{ pixi }}" -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" }

# Detect dead code with vulture and output sorted findings
[group('lint')]
vulture *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe vulture } else { & scripts/run-lint-tool.ps1 -ToolName vulture -DisplayName Vulture -Command "{{ pixi }} vulture {{ FLAGS }} src/ vulture_whitelist.py --min-confidence 60" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Upgrade Python syntax to newer versions
[group('lint')]
pyupgrade *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe pyupgrade } else { Get-ChildItem -Path .\src\intellicrack\ -Recurse -Include "*.py" | ForEach-Object { {{ pixi }} pyupgrade --py312-plus {{ FLAGS }} $_.FullName }; Get-ChildItem -Path .\tests\ -Recurse -Include "*.py" | ForEach-Object { {{ pixi }} pyupgrade --py312-plus {{ FLAGS }} $_.FullName } }

# Apply AI-powered code suggestions with Sourcery
[group('lint')]
sourcery *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe sourcery } else { if (!(Test-Path 'reports/csv')) { New-Item -ItemType Directory -Path 'reports/csv' -Force | Out-Null }; {{ pixi }} sourcery review --fix --csv --no-summary {{ FLAGS }} {{ src }} 2>&1 | Tee-Object -FilePath reports/csv/sourcery_src_findings.csv; {{ pixi }} sourcery review --fix --csv --no-summary {{ FLAGS }} tests 2>&1 | Tee-Object -FilePath reports/csv/sourcery_tests_findings.csv }

# Check docstring validity with pydoclint and output sorted findings
[group('lint')]
pydoclint *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe pydoclint } else { & scripts/run-lint-tool.ps1 -ToolName pydoclint -DisplayName Pydoclint -Command "{{ pixi }} pydoclint {{ FLAGS }} {{ src }}" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Check code line statistics with pygount
[group('lint')]
pygount *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe pygount } else { {{ pixi }} pygount {{ FLAGS }} {{ src }} --format=summary; {{ pixi }} pygount {{ FLAGS }} tests --format=summary }

# Check Python packaging best practices with pyroma
[group('lint')]
pyroma *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe pyroma } else { {{ pixi }} pyroma {{ FLAGS }} . }

# Detect dead code and output sorted findings
[group('lint')]
dead *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe dead } else { & scripts/run-lint-tool.ps1 -ToolName dead -DisplayName "Dead Code" -Command "{{ pixi }} dead --files 'src/' --symbol-allowlist dead_allowlist.txt {{ FLAGS }}" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run type checking with ty and output sorted findings
[group('lint')]
ty *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe ty } else { & scripts/run-lint-tool.ps1 -ToolName ty -DisplayName "Ty Type" -Command "{{ pixi }} ty check {{ FLAGS }} {{ src_and_tests }} --output-format concise" -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Fix PyQt6 QtWidgets.pyi missing collections.abc import
[arg('help', long='help', short='h', value='true')]
[group('setup')]
fix-pyqt6-stubs help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe fix-pyqt6-stubs } else { {{ pixi }} python scripts/fix_pyqt6_stubs.py }

# Populate empty Library/ssl/certs with cacert.pem so pixi 0.69+ stops warning about SSL_CERT_DIR
[arg('help', long='help', short='h', value='true')]
[group('setup')]
fix-pixi-ssl help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe fix-pixi-ssl } else { & scripts/fix-pixi-ssl.ps1 }

# Fix PyQt6 QtCore DLL load failure (Qt 6.10+ needs an OS ICU forwarder this Windows build resolves incorrectly)
[arg('help', long='help', short='h', value='true')]
[group('setup')]
fix-pyqt6-icu help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe fix-pyqt6-icu } else { & scripts/fix-pyqt6-icu.ps1 }

# Run type checking with basedpyright and output sorted findings
[group('lint')]
basedpyright *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe basedpyright } else { & '{{ just_executable() }}' --justfile '{{ justfile() }}' fix-pyqt6-stubs; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & scripts/run-lint-tool.ps1 -ToolName basedpyright -DisplayName BasedPyright -Command "{{ pixi }} basedpyright {{ FLAGS }} src/ --outputjson" -Pixi "{{ pixi }}" -EnvVars 'NODE_OPTIONS=--max-old-space-size=8192' -Flags "{{ FLAGS }}" }

# Run type checking with mypy and output sorted findings
[group('lint')]
mypy *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe mypy } else { & scripts/run-lint-tool.ps1 -ToolName mypy -DisplayName Mypy -Command "{{ pixi }} mypy {{ FLAGS }} {{ src_and_tests }}" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Security linting with bandit and output sorted findings
[group('lint')]
bandit *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe bandit } else { & scripts/run-lint-tool.ps1 -ToolName bandit -DisplayName "Bandit Security" -Command "{{ pixi }} bandit {{ FLAGS }} -r {{ src_and_tests }} -c pyproject.toml" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Security scanning with Semgrep and output sorted findings
[group('lint')]
semgrep *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe semgrep } else { & scripts/run-lint-tool.ps1 -ToolName semgrep -DisplayName Semgrep -Command "{{ pixi }} python scripts/run-semgrep.py --config=.semgrep/logging/ --output {TMPFILE} {{ FLAGS }}" -Pixi "{{ pixi }}" -EnvVars 'PYTHONUTF8=1','PYTHONIOENCODING=utf-8','NO_COLOR=1' -JsonDirect -TextMode -Flags "{{ FLAGS }}" }

# Run flake8 style linting and output sorted findings
[group('lint')]
flake8 *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe flake8 } else { & scripts/run-lint-tool.ps1 -ToolName flake8 -DisplayName Flake8 -Command "{{ pixi }} flake8 {{ FLAGS }} {{ src_and_tests }} --statistics" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run wemake-python-styleguide (strictest linter) and output sorted findings
[group('lint')]
wemake *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe wemake } else { & scripts/run-lint-tool.ps1 -ToolName wemake -DisplayName "Wemake Styleguide" -Command "{{ pixi }} flake8 {{ FLAGS }} {{ src }} --select=WPS,C9 --max-complexity 30 --jobs=1" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} flake8" }

# Run mccabe complexity checker and output sorted findings
[group('lint')]
mccabe *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe mccabe } else { & scripts/run-lint-tool.ps1 -ToolName mccabe -DisplayName "McCabe Complexity" -Command "{{ pixi }} flake8 {{ FLAGS }} {{ src_and_tests }} --select=C901 --max-complexity 30" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run pydocstyle docstring checker and output sorted findings
[group('lint')]
pydocstyle *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe pydocstyle } else { & scripts/run-lint-tool.ps1 -ToolName pydocstyle -DisplayName Pydocstyle -Command "{{ pixi }} pydocstyle {{ FLAGS }} {{ src_and_tests }}" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run radon cyclomatic complexity analysis (C/D rank only, src/ only) and output sorted findings
[group('lint')]
radon *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe radon } else { & scripts/run-lint-tool.ps1 -ToolName radon -DisplayName "Radon Complexity" -Command "{{ pixi }} radon cc {{ src }} -n C -s -a -o SCORE {{ FLAGS }}" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run xenon complexity threshold checker and output sorted findings
[group('lint')]
xenon *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe xenon } else { & scripts/run-lint-tool.ps1 -ToolName xenon -DisplayName "Xenon Complexity" -Command "{{ pixi }} xenon {{ FLAGS }} {{ src_and_tests }} -b B -m C -a C" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run complexipy cognitive complexity analysis and output sorted findings
[group('lint')]
complexipy *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe complexipy } else { & scripts/run-lint-tool.ps1 -ToolName complexipy -DisplayName Complexipy -Command "{{ pixi }} complexipy {{ FLAGS }} src --failed --color no" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run ruff linter and output sorted findings (uses native JSON output for speed)
[group('lint')]
ruff *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe ruff } else { & scripts/run-lint-tool.ps1 -ToolName ruff -DisplayName "Ruff Linter" -Command "{{ pixi }} ruff check {{ FLAGS }} {{ src_and_tests }} --output-format=json -o {TMPFILE}" -JsonDirect -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run ruff format to format Python code
[group('lint')]
ruff-fmt *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe ruff-fmt } else { echo "[Ruff Format] Running..."; {{ pixi }} ruff format {{ FLAGS }} {{ src_and_tests }} 2>&1 | Out-Null; Write-Host "[RUFF FMT] Done" }

# Detect uncalled functions with uncalled and output sorted findings
[group('lint')]
uncalled *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe uncalled } else { & scripts/run-lint-tool.ps1 -ToolName uncalled -DisplayName Uncalled -Command "{{ pixi }} uncalled {{ FLAGS }} --how both src/" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Detect dead code with deadcode and output sorted findings
[group('lint')]
deadcode *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe deadcode } else { & scripts/run-lint-tool.ps1 -ToolName deadcode -DisplayName Deadcode -Command "{{ pixi }} deadcode {{ FLAGS }} src/" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Check docstring coverage with interrogate and output sorted findings
[group('lint')]
interrogate *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe interrogate } else { & scripts/run-lint-tool.ps1 -ToolName interrogate -DisplayName Interrogate -Command "{{ pixi }} interrogate -vv --fail-under 0 --style google {{ FLAGS }} {{ src }}" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Check for dependency issues with deptry and output sorted findings
[group('lint')]
deptry *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe deptry } else { & scripts/run-lint-tool.ps1 -ToolName deptry -DisplayName Deptry -Command "{{ pixi }} deptry --no-ansi {{ FLAGS }} ." -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Check for common misspellings with codespell and output sorted findings
[group('lint')]
codespell *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe codespell } else { & scripts/run-lint-tool.ps1 -ToolName codespell -DisplayName Codespell -Command "{{ pixi }} codespell {{ FLAGS }} src/ tests/ scripts/ docs/ *.md *.toml" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run markdownlint and output sorted findings
[group('lint')]
mdlint *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe mdlint } else { & scripts/run-lint-tool.ps1 -ToolName markdownlint-cli2 -DisplayName "Markdown Lint" -Command "{{ pixi }} {{ mdlint2 }} {{ FLAGS }}" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} {{ mdlint2 }}" }

# Run yamllint and output sorted findings
[group('lint')]
yamllint *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe yamllint } else { & scripts/run-lint-tool.ps1 -ToolName yamllint -DisplayName "YAML Lint" -Command "{{ pixi }} yamllint {{ FLAGS }} ." -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run shellcheck on shell scripts and output sorted findings
[group('lint')]
shellcheck *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe shellcheck } else { & scripts/lint-shellcheck.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run blinter on batch files and output sorted findings
[group('lint')]
blinter *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe blinter } else { & scripts/lint-blinter.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

[doc('Validate JSON files with jsonlint and report syntax errors')]
[group('lint')]
jsonlint *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe jsonlint } else { & scripts/lint-jsonlint.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run tombi TOML linter and output sorted findings
[group('lint')]
tombi *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe tombi } else { & scripts/run-lint-tool.ps1 -ToolName tombi -DisplayName Tombi -Command "{{ pixi }} tombi lint {{ FLAGS }}" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Run pre-commit hooks natively and output sorted findings
[group('lint')]
precommit-hooks *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe precommit-hooks } else { & scripts/run-lint-tool.ps1 -ToolName precommit-hooks -DisplayName "Pre-commit Hooks" -Command "{{ pixi }} python scripts/precommit_hooks.py {{ FLAGS }}" -Pixi "{{ pixi }}" -ReportFormats 'txt','json','xml','csv','sarif' -SuppressStderr -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} python scripts/precommit_hooks.py" }

# Run PSScriptAnalyzer on PowerShell files and output sorted findings
[group('lint')]
psscriptanalyzer *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe psscriptanalyzer } else { & scripts/lint-psscriptanalyzer.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Format JSON files with PowerShell
[arg('help', long='help', short='h', value='true')]
[group('format')]
jsonfmt help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe jsonfmt } else { echo "[JSON Format] Running..."; $jsonFiles = fd -e json --type f --exclude 'package-lock.json' --exclude 'pixi.lock' --exclude 'reports' --exclude '.claude' --exclude '.pixi' --exclude '.git' --exclude 'node_modules' --exclude 'target' --exclude 'vendor' --exclude 'build' --exclude 'dist' 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }; foreach ($file in $jsonFiles) { try { $content = Get-Content $file -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 100; Set-Content -Path $file -Value $content -Encoding utf8 } catch { } }; Write-Host "[JSONFMT] Done" }

# Format YAML files with yamlfmt
[group('format')]
yamlfmt *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe yamlfmt } else { echo "[YAML Format] Running..."; yamlfmt {{ FLAGS }}; echo "[YAML Format] Done" }

# Format TOML files with tombi
[group('format')]
tomlfmt *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe tomlfmt } else { echo "[TOML Format] Running..."; {{ pixi }} tombi format {{ FLAGS }}; echo "[TOML Format] Done" }

# Format Markdown files with markdownlint-cli2 --fix
[group('format')]
mdfmt *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe mdfmt } else { echo "[Markdown Format] Running..."; {{ pixi }} {{ mdlint2 }} --fix {{ FLAGS }} 2>&1 | Out-Null; Write-Host "[MDFMT] Done" }

# Format docstrings in-place with docformatter
[group('format')]
docformatter *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe docformatter } else { echo "[Docformatter] Running..."; {{ pixi }} docformatter --in-place -r {{ FLAGS }} {{ src }} 2>&1 | Out-Null; Write-Host "[DOCFORMATTER] Done" }

# Format pyproject.toml with pyproject-fmt
[group('format')]
pyproject-fmt *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe pyproject-fmt } else { echo "[pyproject-fmt] Running..."; {{ pixi }} pyproject-fmt {{ FLAGS }} pyproject.toml 2>&1 | Out-Null; Write-Host "[PYPROJECT-FMT] Done" }

# Check Python version compatibility with vermin
[group('lint')]
vermin *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe vermin } else { & scripts/run-lint-tool.ps1 -ToolName vermin -DisplayName Vermin -Command "{{ pixi }} vermin --no-tips -vvv --target=3.13 --violations {{ FLAGS }} src/" -TextMode -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

# Watch GitHub Actions CI runs in real-time
[arg('help', long='help', short='h', value='true')]
[group('git')]
watch help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe watch } else { & scripts/watch-ci.ps1 }

# Download CI job logs and artifacts from GitHub Actions
[arg('help', long='help', short='h', value='true')]
[group('git')]
ci-reports help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe ci-reports } else { & scripts/run-logged.ps1 -Recipe ci-reports -Body { & scripts/ci-reports.ps1 -Pixi "{{ pixi }}" }; exit $LASTEXITCODE }

# Cleans Windows NUL file artifacts from the repository
[arg('help', long='help', short='h', value='true')]
[group('git')]
nul-cleanup help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe nul-cleanup } else { & scripts/nul-cleanup.ps1 -Pixi "{{ pixi }}" }

# Generates project structure files (HTA and TXT)
[arg('help', long='help', short='h', value='true')]
[group('git')]
generate-structure help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe generate-structure } else { & scripts/run-logged.ps1 -Recipe generate-structure -Body { & scripts/generate-structure.ps1 -Pixi "{{ pixi }}" }; exit $LASTEXITCODE }

[doc('Regenerate CHANGELOG.md from git history using git-cliff (pass MESSAGE to include a pending commit)')]
[group('git')]
changelog MESSAGE='':
    @if ('{{ MESSAGE }}' -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe changelog } else { & scripts/update-changelog.ps1 -Pixi "{{ pixi }}" -Message '{{ MESSAGE }}' }

[doc('Auto-generate commit message via Gemini API, skip hooks, push to origin, rebasing and retrying if origin moved (flags passed to git push)')]
[group('git')]
git-commit *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe git-commit } else { & scripts/run-logged.ps1 -Recipe git-commit -RecipeArgs '{{ FLAGS }}' -Body { & scripts/git-commit.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }; exit $LASTEXITCODE }

[doc('Rebase local onto origin/main (stash, rebase, pop) - use after merging PRs on GitHub (flags passed to git pull --rebase)')]
[group('git')]
git-rebase *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe git-rebase } else { & scripts/run-logged.ps1 -Recipe git-rebase -RecipeArgs '{{ FLAGS }}' -Body { & scripts/git-rebase.ps1 -Flags "{{ FLAGS }}" }; exit $LASTEXITCODE }

# Full commit with hooks - prompts for message, runs pre-commit hooks, pushes to origin
[group('git')]
git-commit-hooks message:
    @if ('{{ message }}' -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe git-commit-hooks } else { & scripts/run-logged.ps1 -Recipe git-commit-hooks -RecipeArgs '{{ message }}' -Body { & scripts/git-commit-hooks.ps1 -Message '{{ message }}' }; exit $LASTEXITCODE }

# Documentation dispatcher. Usage: just docs [ACTION] [FLAGS...]
# ACTION: build (default), clean, apidoc, linkcheck, pdf, open, rebuild

# Examples: just docs | just docs clean | just docs apidoc | just docs rebuild | just docs build -v
[group('docs')]
docs ACTION='build' *FLAGS:
    @if (('{{ ACTION }}' -match '^--?h(?:elp)?$') -or (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$')) { & scripts/recipe-help.ps1 -Recipe docs } else { & scripts/run-logged.ps1 -Recipe docs -RecipeArgs '{{ ACTION }} {{ FLAGS }}' -Body { & '{{ just_executable() }}' --justfile '{{ justfile() }}' fix-pyqt6-icu; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; & scripts/docs.ps1 -Action "{{ ACTION }}" -Pixi "{{ pixi }}" -Src "{{ src }}" -Flags "{{ FLAGS }}" }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Generate interactive knowledge graph visualization of codebase')]
[group('docs')]
generate-map help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe generate-map } else { & scripts/run-logged.ps1 -Recipe generate-map -Body { & scripts/generate-map.ps1 -Pixi "{{ pixi }}" }; exit $LASTEXITCODE }

# Open knowledge map in browser (Windows)
[arg('help', long='help', short='h', value='true')]
[group('docs')]
open-map help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe open-map } else { $ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[MAP]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $htmlPath = "IntellicrackKnowledgeGraph.html"; if (-not (Test-Path $htmlPath)) { Write-Fail "Knowledge map not found. Run 'just generate-map' first."; exit 1 }; Write-Step "Opening knowledge map in browser..."; Start-Process $htmlPath; Write-Success "Opened in browser" }

[doc('Run all development tools with parallel linting (filter: python|rust|dashboard, --skip tool1,tool2, --workers N)')]
[group('reports')]
run-all-tools *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe run-all-tools } else { & scripts/run-logged.ps1 -Recipe run-all-tools -RecipeArgs '{{ FLAGS }}' -Body { {{ pixi }} python scripts/run-all-tools.py {{ FLAGS }} }; exit $LASTEXITCODE }

# Kill all development processes with automatic elevation
[arg('help', long='help', short='h', value='true')]
[group('system')]
kill help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe kill } else { & scripts/kill-processes.ps1 }

[arg('help', long='help', short='h', value='true')]
[doc('Install Rust development tools via cargo install')]
[group('install')]
install-rust-tools help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe install-rust-tools } else { & scripts/run-logged.ps1 -Recipe install-rust-tools -Body { & scripts/install-rust-tools.ps1 -Pixi "{{ pixi }}" }; exit $LASTEXITCODE }

[doc('Run Clippy linter on Rust hexcore crate')]
[group('lint')]
clippy *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe clippy } else { & scripts/run-lint-tool.ps1 -ToolName clippy -DisplayName Clippy -Command "{{ pixi }} cargo clippy {{ FLAGS }} --all-targets -- -W clippy::all -W clippy::pedantic" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" }

[doc('Check Rust formatting with rustfmt')]
[group('lint')]
rustfmt *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe rustfmt } else { & scripts/run-lint-tool.ps1 -ToolName rustfmt -DisplayName RustFmt -Command "{{ pixi }} cargo fmt {{ FLAGS }} -- --check" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" }

[doc('Run cargo-deny license and advisory checks on Rust hexcore crate')]
[group('lint')]
cargo-deny *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe cargo-deny } else { & scripts/run-lint-tool.ps1 -ToolName cargo-deny -DisplayName CargoDeny -Command "{{ pixi }} cargo deny {{ FLAGS }} check" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} cargo deny" }

[doc('Run Rust tests with cargo-nextest')]
[group('lint')]
nextest *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe nextest } else { & scripts/run-lint-tool.ps1 -ToolName nextest -DisplayName Nextest -Command "{{ pixi }} cargo nextest run {{ FLAGS }} --no-fail-fast" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" }

[doc('Run code coverage with cargo-llvm-cov on Rust hexcore crate')]
[group('lint')]
llvm-cov *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe llvm-cov } else { & scripts/run-lint-tool.ps1 -ToolName llvm-cov -DisplayName LlvmCov -Command "{{ pixi }} cargo llvm-cov nextest {{ FLAGS }} --no-fail-fast" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} cargo llvm-cov" }

[doc('Detect unused Rust dependencies with cargo-machete')]
[group('lint')]
machete *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe machete } else { & scripts/run-lint-tool.ps1 -ToolName machete -DisplayName Machete -Command "{{ pixi }} cargo machete {{ FLAGS }}" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} cargo machete" }

[doc('Run mutation testing with cargo-mutants on Rust hexcore crate (standalone, slow)')]
[group('lint')]
mutants *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe mutants } else { & scripts/run-lint-tool.ps1 -ToolName mutants -DisplayName Mutants -Command "{{ pixi }} cargo mutants {{ FLAGS }} --no-shuffle --timeout 60" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} cargo mutants" }

[doc('Run rust-code-analysis complexity metrics on Rust hexcore crate')]
[group('lint')]
rust-code-analysis *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe rust-code-analysis } else { & scripts/run-lint-tool.ps1 -ToolName rust-code-analysis -DisplayName RustAnalysis -Command "{{ pixi }} rust-code-analysis-cli {{ FLAGS }} -m -p src/" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} rust-code-analysis-cli" }

[doc('Run typos spell checker on Rust hexcore crate')]
[group('lint')]
typos *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe typos } else { & scripts/run-lint-tool.ps1 -ToolName typos -DisplayName Typos -Command "{{ pixi }} typos {{ FLAGS }} ." -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" }

[doc('Run clang-tidy static analysis on the x64dbg-plugin C++ bridge')]
[group('lint')]
clang-tidy *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe clang-tidy } else { & scripts/run-clang-tidy.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}" }

[doc('Check clang-format style on the x64dbg-plugin C++ bridge')]
[group('lint')]
clang-format *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe clang-format } else { & scripts/run-lint-tool.ps1 -ToolName clang-format -DisplayName ClangFormat -Command "{{ pixi }} clang-format --dry-run --Werror -style=file intellicrack_bridge.cpp intellicrack_bridge.h pipe_server.cpp pipe_server.h command_handler.cpp command_handler.h" -TextMode -Pixi "{{ pixi }}" -WorkDir src/x64dbg-plugin -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} clang-format -style=file intellicrack_bridge.cpp intellicrack_bridge.h pipe_server.cpp pipe_server.h command_handler.cpp command_handler.h" }

[doc('Run cppcheck static analysis on the x64dbg-plugin C++ bridge')]
[group('lint')]
cppcheck *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe cppcheck } else { & scripts/run-logged.ps1 -Recipe cppcheck -RecipeArgs '{{ FLAGS }}' -Body { & scripts/build-x64dbg-plugin-compiledb.ps1 -Pixi "{{ pixi }}"; & scripts/fix-cppcheck-cfg.ps1 -Pixi "{{ pixi }}"; & scripts/run-lint-tool.ps1 -ToolName cppcheck -DisplayName Cppcheck -Command "{{ pixi }} cppcheck --project=src/x64dbg-plugin/build_lint/compile_commands.json --enable=warning,performance,portability,style --inconclusive --suppress=missingIncludeSystem --template=gcc" -TextMode -Pixi "{{ pixi }}" -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} cppcheck --project=src/x64dbg-plugin/build_lint/compile_commands.json" }; exit $LASTEXITCODE }

[doc('Check cmake-format style on the x64dbg-plugin CMakeLists.txt')]
[group('lint')]
cmake-format *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe cmake-format } else { & scripts/run-lint-tool.ps1 -ToolName cmake-format -DisplayName CmakeFormat -Command "{{ pixi }} cmake-format -c src/x64dbg-plugin/.cmake-format.yaml --check src/x64dbg-plugin/CMakeLists.txt" -TextMode -Pixi "{{ pixi }}" -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} cmake-format -c src/x64dbg-plugin/.cmake-format.yaml src/x64dbg-plugin/CMakeLists.txt" }

[doc('Run cmake-lint style checks on the x64dbg-plugin CMakeLists.txt')]
[group('lint')]
cmake-lint *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe cmake-lint } else { & scripts/run-lint-tool.ps1 -ToolName cmake-lint -DisplayName CmakeLint -Command "{{ pixi }} cmake-lint --suppress-decorations -c src/x64dbg-plugin/.cmake-format.yaml -- src/x64dbg-plugin/CMakeLists.txt" -TextMode -Pixi "{{ pixi }}" -ReportFormats 'txt','json','xml','csv','sarif','sql' -Flags "{{ FLAGS }}" -PassthruExe "{{ pixi }} cmake-lint -c src/x64dbg-plugin/.cmake-format.yaml -- src/x64dbg-plugin/CMakeLists.txt" }

# Run MegaLinter (Docker) on src/. Switches Docker Desktop to Linux containers,
# installs the MegaLinter image, runs mega-linter-runner, saves findings to
# reports/megalinter, then uninstalls both the container and the image and
# restores Docker Desktop to its original engine. The image is installed and
# uninstalled on every single run, so every run re-downloads a few GB -- pass
# --keep-image to leave it installed while iterating.
# Refuses to run while a QEMU/Windows Sandbox VM is up -- see scripts/run-megalinter.ps1.
[doc('Run MegaLinter (Docker) on src/ -- see scripts/run-megalinter.ps1 for the full lifecycle')]
[group('lint')]
megalint *FLAGS:
    @if (('{{ FLAGS }}' -split ' ') -match '^--?h(?:elp)?$') { & scripts/recipe-help.ps1 -Recipe megalint } else { & scripts/run-logged.ps1 -Recipe megalint -RecipeArgs '{{ FLAGS }}' -Body { & scripts/run-megalinter.ps1 -Flags "{{ FLAGS }}" }; exit $LASTEXITCODE }

[arg('help', long='help', short='h', value='true')]
[doc('Generate unified HTML lint dashboard from all tool findings')]
[group('reports')]
lint-dashboard help='false':
    @if ('{{ help }}' -eq 'true') { & scripts/recipe-help.ps1 -Recipe lint-dashboard } else { echo "[Dashboard] Generating..."; {{ pixi }} python scripts/lint_report.py report --input-dir reports/json --output reports/lint_dashboard.html --title "Intellicrack Lint Dashboard" }

# Recipe aliases — match the display names shown by `just run-all-tools`
# and common natural-language variants so any reasonable name works.

alias markdown := mdlint
alias markdownlint := mdlint
alias md-lint := mdlint
alias mdformat := mdfmt
alias md-fmt := mdfmt

alias yaml := yamllint
alias yaml-lint := yamllint
alias yaml-fmt := yamlfmt

alias json-lint := jsonlint
alias json-fmt := jsonfmt

alias toml-fmt := tomlfmt
alias toml := tombi
alias toml-lint := tombi
alias pyproject := pyproject-fmt

alias shell := shellcheck
alias shell-check := shellcheck

alias bat := blinter
alias batch := blinter

alias psscript := psscriptanalyzer
alias ps-script := psscriptanalyzer
alias powershell := psscriptanalyzer
alias pwsh := psscriptanalyzer

alias dashboard := lint-dashboard

alias mega-lint := megalint
alias mega_lint := megalint

alias rustanalysis := rust-code-analysis
alias rust-analysis := rust-code-analysis

alias cargodeny := cargo-deny
alias cargo-clippy := clippy
alias cargo-nextest := nextest
alias cargo-machete := machete

alias llvmcov := llvm-cov

alias rust-fmt := rustfmt

alias precommithooks := precommit-hooks
alias precommit := precommit-hooks
alias pre-commit := precommit-hooks

alias deadcode-tool := deadcode
alias dead-code := deadcode

alias pyright := basedpyright
alias based-pyright := basedpyright

alias code-spell := codespell
alias doc-formatter := docformatter
