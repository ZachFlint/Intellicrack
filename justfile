# Intellicrack Commands
# Configure shell for Windows

set unstable := true
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

pixi := "pixi run"
src := "src/intellicrack"
src_and_tests := "src/intellicrack/ tests/"

# Complete installation with all post-install tasks
[group('install')]
install:
    @& scripts/install-all.ps1

# Remove pixi environment
[group('install')]
uninstall:
    @& scripts/uninstall.ps1

[doc('Download and install the latest Ghidra reverse engineering tool')]
[group('install')]
install-ghidra:
    @& scripts/install-ghidra.ps1

[doc('Download and install the latest radare2 reverse engineering framework')]
[group('install')]
install-radare2:
    @& scripts/install-radare2.ps1

[doc('Build the Rust hex editor core (intellicrack-hexcore)')]
[group('build')]
build-hexcore:
    cd src/intellicrack-hexcore && {{ pixi }} maturin develop --release

[doc('Run Rust hex editor core tests')]
[group('test')]
test-hexcore:
    cd src/intellicrack-hexcore && {{ pixi }} cargo test

[doc('Clean Rust hex editor core build artifacts')]
[group('build')]
clean-hexcore:
    cd src/intellicrack-hexcore && {{ pixi }} cargo clean

[doc('Download and install the latest QEMU emulator')]
[group('install')]
install-qemu:
    @& scripts/install-qemu.ps1

[doc('Download and install the latest x64dbg debugger')]
[group('install')]
install-x64dbg:
    @& scripts/install-x64dbg.ps1

[doc('Download and install the latest Cutter reverse engineering tool')]
[group('install')]
install-cutter:
    @& scripts/install-cutter.ps1

[doc('Build x64dbg bridge plugin from source and deploy to x64dbg plugins directory')]
[group('install')]
install-x64dbg-plugin:
    @& scripts/install-x64dbg-plugin.ps1

# Clean all build artifacts (Python, test caches)
[group('cleanup')]
clean:
    @& scripts/clean.ps1 -Pixi "{{ pixi }}" -SrcAndTests "{{ src_and_tests }}"

# Launch interactive Windows Sandbox for Intellicrack testing (READ-ONLY)
[group('sandbox')]
sandbox:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType interactive }

# Launch interactive Windows Sandbox with READ-WRITE access (changes persist to host)
[group('sandbox')]
sandbox-rw:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType interactive-rw }

# Launch sandbox and run hardware spoofer registry tests
[group('sandbox')]
sandbox-test-registry:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType registry }

# Quick unit tests - runs in Windows Sandbox for isolation
[group('test')]
test:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType unit }

# Full test suite - runs in Windows Sandbox for isolation
[group('test')]
test-all:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType all }

# Coverage report - runs in Windows Sandbox with 95%+ coverage requirement
[group('test')]
test-coverage:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType coverage }

# Runs tests for a specific module in Windows Sandbox
[group('test')]
test-module module:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType module -Module "{{ module }}" }

# Benchmarks - runs in Windows Sandbox
[group('test')]
test-bench:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType bench }

# Integration tests - runs in Windows Sandbox
[group('test')]
test-integration:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType integration }

# End-to-end tests - runs in Windows Sandbox
[group('test')]
test-e2e:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType e2e }

# Quick smoke test - runs in Windows Sandbox
[group('test')]
test-smoke:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType smoke }

# Module tests with coverage - runs in Windows Sandbox
[group('test')]
test-module-cov module:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType module-cov -Module "{{ module }}" }

# Parallel tests - runs in Windows Sandbox
[group('test')]
test-parallel:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType parallel }

# Retest failed tests - runs in Windows Sandbox
[group('test')]
test-failed:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType failed }

# Verbose tests - runs in Windows Sandbox
[group('test')]
test-verbose:
    @gsudo { & "D:\Sandbox\shared\launch_sandbox_test.ps1" -TestType verbose }

# Verify no mocks or fake data
[group('test')]
test-verify-real:
    @& scripts/test-verify-real.ps1 -Pixi "{{ pixi }}"

# Lint code with ruff
[group('lint')]
lint *FLAGS:
    @& scripts/lint-check.ps1 -Pixi "{{ pixi }}" -Src "{{ src }}" -Flags "{{ FLAGS }}"

# Fix linting issues automatically
[group('lint')]
lint-fix *FLAGS:
    @& scripts/lint-fix.ps1 -Pixi "{{ pixi }}" -Src "{{ src }}" -Flags "{{ FLAGS }}"

# Find dead code, secrets, and risky flows with skylos
[group('lint')]
skylos *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName skylos -DisplayName Skylos -Command "{{ pixi }} skylos {{ FLAGS }} --json {{ src }}" -Pixi "{{ pixi }}" -ReportFormats 'txt','json','xml','csv','sarif','sql'

# Detect dead code with vulture and output sorted findings
[group('lint')]
vulture *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName vulture -DisplayName Vulture -Command "{{ pixi }} vulture {{ FLAGS }} src/ vulture_whitelist.py --min-confidence 60" -TextMode -Pixi "{{ pixi }}"

# Upgrade Python syntax to newer versions
[group('lint')]
pyupgrade *FLAGS:
    @Get-ChildItem -Path .\src\intellicrack\ -Recurse -Include "*.py" | ForEach-Object { {{ pixi }} pyupgrade --py312-plus {{ FLAGS }} $_.FullName }
    @Get-ChildItem -Path .\tests\ -Recurse -Include "*.py" | ForEach-Object { {{ pixi }} pyupgrade --py312-plus {{ FLAGS }} $_.FullName }

# Apply AI-powered code suggestions with Sourcery
[group('lint')]
sourcery *FLAGS:
    @if (!(Test-Path 'reports/csv')) { New-Item -ItemType Directory -Path 'reports/csv' -Force | Out-Null }
    @{{ pixi }} sourcery review --fix --csv --no-summary {{ FLAGS }} {{ src }} 2>&1 | Tee-Object -FilePath reports/csv/sourcery_src_findings.csv
    @{{ pixi }} sourcery review --fix --csv --no-summary {{ FLAGS }} tests 2>&1 | Tee-Object -FilePath reports/csv/sourcery_tests_findings.csv

# Check docstring validity with darglint and output sorted findings
[group('lint')]
darglint *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName darglint -DisplayName Darglint -Command "{{ pixi }} darglint {{ FLAGS }} {{ src }}" -TextMode -Pixi "{{ pixi }}"

# Check docstring validity with pydoclint and output sorted findings
[group('lint')]
pydoclint *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName pydoclint -DisplayName Pydoclint -Command "{{ pixi }} pydoclint {{ FLAGS }} {{ src }}" -TextMode -Pixi "{{ pixi }}"

# Check code line statistics with pygount
[group('lint')]
pygount *FLAGS:
    @{{ pixi }} pygount {{ FLAGS }} {{ src }} --format=summary
    @{{ pixi }} pygount {{ FLAGS }} tests --format=summary

# Check Python packaging best practices with pyroma
[group('lint')]
pyroma *FLAGS:
    @{{ pixi }} pyroma {{ FLAGS }} .

# Detect dead code and output sorted findings
[group('lint')]
dead *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName dead -DisplayName "Dead Code" -Command "{{ pixi }} dead --files 'src/' --symbol-allowlist dead_allowlist.txt {{ FLAGS }}" -TextMode -Pixi "{{ pixi }}"

# Run type checking with ty and output sorted findings
[group('lint')]
ty *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName ty -DisplayName "Ty Type" -Command "{{ pixi }} ty check {{ FLAGS }} {{ src_and_tests }} --output-format concise" -Pixi "{{ pixi }}"

# Fix PyQt6 QtWidgets.pyi missing collections.abc import
[group('setup')]
fix-pyqt6-stubs:
    @{{ pixi }} python scripts/fix_pyqt6_stubs.py

# Run type checking with basedpyright and output sorted findings
[group('lint')]
basedpyright *FLAGS: fix-pyqt6-stubs
    @& scripts/run-lint-tool.ps1 -ToolName basedpyright -DisplayName BasedPyright -Command "{{ pixi }} basedpyright {{ FLAGS }} src/ --outputjson" -Pixi "{{ pixi }}" -EnvVars 'NODE_OPTIONS=--max-old-space-size=8192'

# Run type checking with mypy and output sorted findings
[group('lint')]
mypy *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName mypy -DisplayName Mypy -Command "{{ pixi }} mypy {{ FLAGS }} {{ src_and_tests }}" -TextMode -Pixi "{{ pixi }}"

# Security linting with bandit and output sorted findings
[group('lint')]
bandit *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName bandit -DisplayName "Bandit Security" -Command "{{ pixi }} bandit {{ FLAGS }} -r {{ src_and_tests }} -c pyproject.toml" -TextMode -Pixi "{{ pixi }}"

# Security scanning with Semgrep and output sorted findings
[group('lint')]
semgrep *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName semgrep -DisplayName Semgrep -Command "semgrep scan --config=auto --json --timeout 30 {{ FLAGS }} src/" -Pixi "{{ pixi }}" -EnvVars 'PYTHONUTF8=1','PYTHONIOENCODING=utf-8' -SuppressStderr

# Run flake8 style linting and output sorted findings
[group('lint')]
flake8 *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName flake8 -DisplayName Flake8 -Command "{{ pixi }} flake8 {{ FLAGS }} {{ src_and_tests }} --statistics" -TextMode -Pixi "{{ pixi }}"

# Run wemake-python-styleguide (strictest linter) and output sorted findings
[group('lint')]
wemake *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName wemake -DisplayName "Wemake Styleguide" -Command "{{ pixi }} flake8 {{ FLAGS }} {{ src }} --select=WPS,C9 --max-complexity 10" -TextMode -Pixi "{{ pixi }}"

# Run mccabe complexity checker and output sorted findings
[group('lint')]
mccabe *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName mccabe -DisplayName "McCabe Complexity" -Command "{{ pixi }} flake8 {{ FLAGS }} {{ src_and_tests }} --select=C901 --max-complexity 10" -TextMode -Pixi "{{ pixi }}"

# Run pydocstyle docstring checker and output sorted findings
[group('lint')]
pydocstyle *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName pydocstyle -DisplayName Pydocstyle -Command "{{ pixi }} pydocstyle {{ FLAGS }} {{ src_and_tests }}" -TextMode -Pixi "{{ pixi }}"

# Run radon cyclomatic complexity analysis (C/D rank only, src/ only) and output sorted findings
[group('lint')]
radon *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName radon -DisplayName "Radon Complexity" -Command "{{ pixi }} radon cc {{ src }} -n C -s -a -o SCORE {{ FLAGS }}" -TextMode -Pixi "{{ pixi }}"

# Run xenon complexity threshold checker and output sorted findings
[group('lint')]
xenon *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName xenon -DisplayName "Xenon Complexity" -Command "{{ pixi }} xenon {{ FLAGS }} {{ src_and_tests }} -b B -m C -a C" -TextMode -Pixi "{{ pixi }}"

# Run complexipy cognitive complexity analysis and output sorted findings
[group('lint')]
complexipy *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName complexipy -DisplayName Complexipy -Command "{{ pixi }} complexipy {{ FLAGS }} src --failed --color no" -TextMode -Pixi "{{ pixi }}"

# Run ruff linter and output sorted findings (uses native JSON output for speed)
[group('lint')]
ruff *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName ruff -DisplayName "Ruff Linter" -Command "{{ pixi }} ruff check {{ FLAGS }} {{ src_and_tests }} --output-format=json -o {TMPFILE}" -JsonDirect -Pixi "{{ pixi }}"

# Run ruff format to format Python code
[group('lint')]
ruff-fmt *FLAGS:
    @echo "[Ruff Format] Running..."
    @{{ pixi }} ruff format {{ FLAGS }} {{ src_and_tests }} 2>&1 | Out-Null; Write-Host "[RUFF FMT] Done"

# Detect uncalled functions with uncalled and output sorted findings
[group('lint')]
uncalled *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName uncalled -DisplayName Uncalled -Command "{{ pixi }} uncalled {{ FLAGS }} --how both src/" -TextMode -Pixi "{{ pixi }}"

# Detect dead code with deadcode and output sorted findings
[group('lint')]
deadcode *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName deadcode -DisplayName Deadcode -Command "{{ pixi }} deadcode {{ FLAGS }} src/" -TextMode -Pixi "{{ pixi }}"

# Check docstring coverage with interrogate and output sorted findings
[group('lint')]
interrogate *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName interrogate -DisplayName Interrogate -Command "{{ pixi }} interrogate -vv --fail-under 0 --style google {{ FLAGS }} {{ src }}" -TextMode -Pixi "{{ pixi }}"

# Check for dependency issues with deptry and output sorted findings
[group('lint')]
deptry *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName deptry -DisplayName Deptry -Command "{{ pixi }} deptry --no-ansi {{ FLAGS }} ." -TextMode -Pixi "{{ pixi }}"

# Check for common misspellings with codespell and output sorted findings
[group('lint')]
codespell *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName codespell -DisplayName Codespell -Command "{{ pixi }} codespell {{ FLAGS }} src/ tests/ scripts/ docs/ *.md *.toml" -TextMode -Pixi "{{ pixi }}"

# Run markdownlint and output sorted findings
[group('lint')]
mdlint *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName markdownlint -DisplayName "Markdown Lint" -Command "{{ pixi }} markdownlint {{ FLAGS }} '**/*.md' --ignore node_modules --ignore .venv* --ignore .pixi --ignore .claude --ignore build --ignore dist --ignore tools" -TextMode -Pixi "{{ pixi }}"

# Run yamllint and output sorted findings
[group('lint')]
yamllint *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName yamllint -DisplayName "YAML Lint" -Command "{{ pixi }} yamllint {{ FLAGS }} ." -TextMode -Pixi "{{ pixi }}"

# Run shellcheck on shell scripts and output sorted findings
[group('lint')]
shellcheck *FLAGS:
    @& scripts/lint-shellcheck.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}"

# Run blinter on batch files and output sorted findings
[group('lint')]
blinter *FLAGS:
    @& scripts/lint-blinter.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}"

[doc('Validate JSON files with jsonlint and report syntax errors')]
[group('lint')]
jsonlint *FLAGS:
    @& scripts/lint-jsonlint.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}"

# Run taplo TOML linter and output sorted findings
[group('lint')]
taplo *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName taplo -DisplayName Taplo -Command "taplo check {{ FLAGS }}" -TextMode -Pixi "{{ pixi }}"

# Run pre-commit hooks natively and output sorted findings
[group('lint')]
precommit-hooks *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName precommit-hooks -DisplayName "Pre-commit Hooks" -Command "{{ pixi }} python scripts/precommit_hooks.py {{ FLAGS }}" -Pixi "{{ pixi }}" -ReportFormats 'txt','json','xml','csv','sarif' -SuppressStderr

# Run PSScriptAnalyzer on PowerShell files and output sorted findings
[group('lint')]
psscriptanalyzer *FLAGS:
    @& scripts/lint-psscriptanalyzer.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}"

# Format JSON files with PowerShell
[group('format')]
jsonfmt:
    @echo "[JSON Format] Running..."
    @$jsonFiles = fd -e json --type f --exclude 'package-lock.json' --exclude 'pixi.lock' --exclude 'reports' --exclude '.claude' --exclude '.pixi' --exclude 'node_modules' 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }; foreach ($file in $jsonFiles) { try { $content = Get-Content $file -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 100; Set-Content -Path $file -Value $content -Encoding utf8 } catch { } }; Write-Host "[JSONFMT] Done"

# Format YAML files with yamlfmt
[group('format')]
yamlfmt *FLAGS:
    @echo "[YAML Format] Running..."; yamlfmt {{ FLAGS }}; echo "[YAML Format] Done"

# Format TOML files with taplo
[group('format')]
tomlfmt *FLAGS:
    @echo "[TOML Format] Running..."; taplo fmt {{ FLAGS }}; echo "[TOML Format] Done"

# Format Markdown files with markdownlint --fix
[group('format')]
mdfmt *FLAGS:
    @echo "[Markdown Format] Running..."
    @{{ pixi }} markdownlint --fix {{ FLAGS }} "**/*.md" --ignore node_modules --ignore .venv* --ignore .pixi --ignore .claude --ignore build --ignore dist --ignore tools 2>&1 | Out-Null; Write-Host "[MDFMT] Done"

# Format docstrings in-place with docformatter
[group('format')]
docformatter *FLAGS:
    @echo "[Docformatter] Running..."
    @{{ pixi }} docformatter --in-place -r {{ FLAGS }} {{ src }} 2>&1 | Out-Null; Write-Host "[DOCFORMATTER] Done"

# Format pyproject.toml with pyproject-fmt
[group('format')]
pyproject-fmt *FLAGS:
    @echo "[pyproject-fmt] Running..."
    @{{ pixi }} pyproject-fmt {{ FLAGS }} pyproject.toml 2>&1 | Out-Null; Write-Host "[PYPROJECT-FMT] Done"

# Check Python version compatibility with vermin
[group('lint')]
vermin *FLAGS:
    @& scripts/run-lint-tool.ps1 -ToolName vermin -DisplayName Vermin -Command "{{ pixi }} vermin --no-tips -vvv --target=3.13 --violations {{ FLAGS }} src/" -TextMode -Pixi "{{ pixi }}"

# Watch GitHub Actions CI runs in real-time
[group('git')]
watch:
    @& scripts/watch-ci.ps1

# Download CI job logs and artifacts from GitHub Actions
[group('git')]
ci-reports:
    @& scripts/ci-reports.ps1 -Pixi "{{ pixi }}"

# Cleans Windows NUL file artifacts from the repository
[group('git')]
nul-cleanup:
    @& scripts/nul-cleanup.ps1 -Pixi "{{ pixi }}"

# Generates project structure files (HTA and TXT)
[group('git')]
generate-structure:
    @& scripts/generate-structure.ps1 -Pixi "{{ pixi }}"

[doc('Regenerate CHANGELOG.md from git history using git-cliff (pass MESSAGE to include a pending commit)')]
[group('git')]
changelog MESSAGE='':
    @& scripts/update-changelog.ps1 -Pixi "{{ pixi }}" -Message '{{ MESSAGE }}'

[doc('Auto-generate commit message via Gemini API, skip hooks, push to origin (flags passed to git push)')]
[group('git')]
git-commit *FLAGS:
    @& scripts/git-commit.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}"

[doc('Rebase local onto origin/main (stash, rebase, pop) - use after merging PRs on GitHub (flags passed to git pull --rebase)')]
[group('git')]
git-rebase *FLAGS:
    @& scripts/git-rebase.ps1 -Flags "{{ FLAGS }}"

# Full commit with hooks - prompts for message, runs pre-commit hooks, pushes to origin
[group('git')]
git-commit-hooks message:
    @& scripts/git-commit-hooks.ps1 -Message '{{ message }}'

# Generate Sphinx documentation
[group('docs')]
docs-build *FLAGS:
    @& scripts/docs-build.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}"

# Clean documentation build
[group('docs')]
docs-clean:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; Write-Step "Cleaning documentation build..."; if (Test-Path "docs\build") { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue docs\build\*; Write-Success "Documentation build cleaned" } else { Write-Success "Nothing to clean" }

# Regenerate API documentation from code
[group('docs')]
docs-apidoc *FLAGS:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; Write-Step "Generating API documentation..."; try { {{ pixi }} sphinx-apidoc {{ FLAGS }} -f -o docs/source {{ src }} 2>&1 | ForEach-Object { Write-Host "  $_" }; if ($LASTEXITCODE -ne 0) { throw "sphinx-apidoc failed" }; Write-Success "API documentation generated" } catch { Write-Fail "Generation failed: $_"; exit 1 }

# Full documentation rebuild
[group('docs')]
docs-rebuild: docs-clean docs-apidoc docs-build
    @$e = [char]27; Write-Host "`n$e[1;32m=== Documentation Rebuild Complete ===$e[0m"; Write-Host "View at: docs/build/html/index.html`n"

# Open documentation in browser (Windows)
[group('docs')]
docs-open:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[DOCS]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $docPath = "docs\build\html\index.html"; if (-not (Test-Path $docPath)) { Write-Fail "Documentation not found. Run 'just docs-build' first."; exit 1 }; Write-Step "Opening documentation in browser..."; Start-Process $docPath; Write-Success "Opened in browser"

# Build PDF documentation
[group('docs')]
docs-pdf *FLAGS:
    @& scripts/docs-pdf.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}"

# Check documentation links
[group('docs')]
docs-linkcheck *FLAGS:
    @& scripts/docs-linkcheck.ps1 -Pixi "{{ pixi }}" -Flags "{{ FLAGS }}"

[doc('Generate interactive knowledge graph visualization of codebase')]
[group('docs')]
generate-map:
    @& scripts/generate-map.ps1 -Pixi "{{ pixi }}"

# Open knowledge map in browser (Windows)
[group('docs')]
open-map:
    @$ErrorActionPreference = 'Stop'; $e = [char]27; function Write-Step { param($msg) Write-Host "$e[36m[MAP]$e[0m $msg" }; function Write-Success { param($msg) Write-Host "  $e[32m[OK]$e[0m $msg" }; function Write-Fail { param($msg) Write-Host "  $e[31m[FAIL]$e[0m $msg" }; $htmlPath = "IntellicrackKnowledgeGraph.html"; if (-not (Test-Path $htmlPath)) { Write-Fail "Knowledge map not found. Run 'just generate-map' first."; exit 1 }; Write-Step "Opening knowledge map in browser..."; Start-Process $htmlPath; Write-Success "Opened in browser"

[doc('Run all development tools with parallel linting (filter: python|rust|dashboard, --skip tool1,tool2, --workers N)')]
[group('reports')]
run-all-tools *FLAGS:
    @{{ pixi }} python scripts/run-all-tools.py {{ FLAGS }}

# Kill all development processes with automatic elevation
[group('system')]
kill:
    @& scripts/kill-processes.ps1

# Build CLI Launcher (release, max optimization) and deploy to CLI Coding/
[group('build')]
build-cli-launcher:
    @Push-Location 'CLI Coding/launcher'; cargo build --release; if ($LASTEXITCODE -eq 0) { Copy-Item -Force 'target/release/cli-launcher.exe' '../CLI Launcher.exe'; Write-Host 'Deployed to: CLI Coding/CLI Launcher.exe' -ForegroundColor Green } else { Write-Host 'Build failed.' -ForegroundColor Red; exit 1 }; Pop-Location

[doc('Install Rust development tools via cargo install')]
[group('install')]
install-rust-tools:
    @& scripts/install-rust-tools.ps1 -Pixi "{{ pixi }}"

[doc('Run Clippy linter on Rust hexcore crate')]
[group('lint')]
clippy:
    @& scripts/run-lint-tool.ps1 -ToolName clippy -DisplayName Clippy -Command "{{ pixi }} cargo clippy --all-targets -- -W clippy::all -W clippy::pedantic" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Check Rust formatting with rustfmt')]
[group('lint')]
rustfmt:
    @& scripts/run-lint-tool.ps1 -ToolName rustfmt -DisplayName RustFmt -Command "{{ pixi }} cargo fmt -- --check" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Run cargo-deny license and advisory checks on Rust hexcore crate')]
[group('lint')]
cargo-deny:
    @& scripts/run-lint-tool.ps1 -ToolName cargo-deny -DisplayName CargoDeny -Command "{{ pixi }} cargo deny check" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Run Rust tests with cargo-nextest')]
[group('lint')]
nextest:
    @& scripts/run-lint-tool.ps1 -ToolName nextest -DisplayName Nextest -Command "{{ pixi }} cargo nextest run --no-fail-fast" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Run code coverage with cargo-llvm-cov on Rust hexcore crate')]
[group('lint')]
llvm-cov:
    @& scripts/run-lint-tool.ps1 -ToolName llvm-cov -DisplayName LlvmCov -Command "{{ pixi }} cargo llvm-cov nextest run --no-fail-fast" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Detect unused Rust dependencies with cargo-machete')]
[group('lint')]
machete:
    @& scripts/run-lint-tool.ps1 -ToolName machete -DisplayName Machete -Command "{{ pixi }} cargo machete" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Run mutation testing with cargo-mutants on Rust hexcore crate (standalone, slow)')]
[group('lint')]
mutants:
    @& scripts/run-lint-tool.ps1 -ToolName mutants -DisplayName Mutants -Command "{{ pixi }} cargo mutants --no-shuffle --timeout 60" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Run rust-code-analysis complexity metrics on Rust hexcore crate')]
[group('lint')]
rust-code-analysis:
    @& scripts/run-lint-tool.ps1 -ToolName rust-code-analysis -DisplayName RustAnalysis -Command "{{ pixi }} rust-code-analysis-cli -m -p src/" -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Run typos spell checker on Rust hexcore crate')]
[group('lint')]
typos:
    @& scripts/run-lint-tool.ps1 -ToolName typos -DisplayName Typos -Command "{{ pixi }} typos ." -TextMode -Pixi "{{ pixi }}" -WorkDir src/intellicrack-hexcore -ReportFormats 'txt','json','xml','csv','sarif','sql'

[doc('Generate unified HTML lint dashboard from all tool findings')]
[group('reports')]
lint-dashboard:
    @echo "[Dashboard] Generating..."
    @{{ pixi }} python scripts/lint_report.py report --input-dir reports/json --output reports/lint_dashboard.html --title "Intellicrack Lint Dashboard"
