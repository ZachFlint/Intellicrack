# Intellicrack

## Project Overview

**Intellicrack** - Advanced binary analysis platform **SPECIFICALLY AND
EXCLUSIVELY** designed for analyzing software and cracking licensing
protections. This tool focuses **SOLELY** on defeating software licensing
mechanisms, registration systems, trial limitations, and copy protection
schemes.

### EXPLICIT TOOL SCOPE - CRITICAL

**What Intellicrack IS:**

- **SOFTWARE LICENSING CRACKER** - Defeats licensing protections, serial
  validation, and registration systems
- **PROTECTION ANALYZER** - Analyzes and bypasses copy protection, trial
  limitations, and activation mechanisms
- **BINARY PATCHER** - Modifies binaries to remove licensing checks and
  protection routines
- **LICENSE KEYGEN CREATOR** - Generates valid license keys and registration
  codes

**What Intellicrack IS NOT:**

- **NOT a malware creation tool** - No malware injection, payload delivery, or
  virus creation
- **NOT a system exploit framework** - No OS exploitation, privilege escalation,
  or system compromise
- **NOT a network attack tool** - No network intrusion, packet injection, or
  remote exploitation
- **NOT a data theft tool** - No credential harvesting, data exfiltration, or
  information stealing

**SCOPE LIMITATION:** This tool is **EXCLUSIVELY** for analyzing and defeating
software licensing protections. Any functionality must be directly related to
cracking software protections, NOT creating other types of exploits.

### Project Intent & Security Research Purpose

This tool is developed for **defensive security research** to help software
developers:

- **Identify weaknesses** in their own licensing protection mechanisms by using
  Intellicrack in a controlled enviornment to crack their software, so they can
  strengthen the licensing protections to prevent future attacks.
- **Test robustness** of licensing, registration, and activation systems in
  controlled environments
- **Strengthen licensing defenses** against cracking attempts by understanding
  bypass techniques
- **Validate protection effectiveness** of their own software's licensing
  mechanisms before deployment

**Critical Context:** Intellicrack requires functionally real and robust
licensing cracking capabilities to serve as an effective security research tool.
All components must be production-ready to accurately defeat protection
mechanisms and provide meaningful security insights to developers working to
improve their software's licensing security.

**Usage Environment:** This tool operates exclusively in controlled, isolated
research environments for authorized security assessment of proprietary software
licensing systems by their own developers and security teams.

**TOOLS**

## USE THESE TOOLS

1. rg instead of grep
2. fd instead of find
3. tree is installed

## CRITICAL: SHELL USAGE

- **Always use `pwsh` (PowerShell 7) for PowerShell commands, NEVER `powershell.exe` (PowerShell 5)**
- When executing PowerShell commands, use `pwsh -Command '...'` or `pwsh -File ...`

## CRITICAL: VIRTUAL ENVIRONMENT USAGE

**Environment Usage:**

- **Pixi environment location**: `D:\Intellicrack\.pixi\envs\default`
- **Activation**: `pixi shell` or use `pixi run <command>`
- **Claude Code runs natively on Windows**

## 🔧 CRITICAL CODING RULES

### Code Style

- **NEVER add unnecessary comments** - Keep code clean
- **NO explanatory comments** about imports, fixes, or obvious code
- **Comments ONLY when user explicitly requests**
- **NEVER use emojis in code or responses unless explicitly requested** - No
  emojis in any output.
- **ALL code must include proper type hints and annotations** - Every function,
  method, and variable must have explicit type checking.
- **Use Google-style docstrings** for all functions, methods, and classes
- **ALL code must pass `ruff check`** - Lint all new and modified code with ruff
  and fix all findings before considering work complete
- **ALL code must be fully basedpyright compliant** - Code must be absolutely and
  completely type correct. No basedpyright findings are acceptable under any
  circumstance. Every type annotation must be precise and correct.
- **NEVER use type suppression comments** - Under no circumstance may any
  type-ignore directive, pyright-ignore directive, noqa directive for type
  issues, or any other mechanism to suppress type checking findings be used.
  This includes ALL forms of inline suppression comments. Fix the actual type
  error instead.
- **NEVER edit the basedpyright configuration** - The `[tool.basedpyright]` section in
  `pyproject.toml` must never be modified to weaken type checking strictness,
  add exclusions, or suppress diagnostics. The basedpyright config is locked and
  immutable.
- **ALL code must pass `darglint`** - Full darglint compliance required with zero
  findings. Docstrings must exactly match signatures: parameters, types, returns,
  raises, and yields. No errors or warnings of any kind are acceptable.
- **NEVER suppress darglint findings** - No inline suppression directives, disable
  comments, or any mechanism to ignore darglint findings. Fix the docstring instead.
- **NEVER weaken darglint configuration** - The darglint config is locked and
  immutable. Never disable rules, add ignores, exclude files, or reduce strictness.
- **Follow common development principles (where relevant) including:** •
  **SOLID** (Single Responsibility Principle, Open/Closed Principle, Liskov
  Substitution Principle, Interface Segregation Principle, and Dependency
  Inversion Principle) • **DRY** (Don't Repeat Yourself) • **KISS** (Keep It
  Simple, Stupid)

### Implementation Standards

- **ALL CODE MUST BE WRITTEN FOR FULL COMPATIBLITY WITH WINDOWS PLATFORMS AS A
  PRIORITY.**
- **NO STUBS, MOCKS, OR PLACEHOLDERS** - ALL code must be FULLY FUNCTIONAL
- **NO TODO COMMENTS** - Implement REAL functionality immediately
- **NO SIMULATION MODES** - Real licensing cracking tool only
- **NEVER delete method bindings** - CREATE MISSING FUNCTIONS instead
- **ALL METHODS MUST WORK ON REAL BINARIES** - Specifically for cracking
  licensing protections
- **MAINTAIN FUNCTIONALITY** - Never sacrifice features for "cleaner" code
- **SCOPE ENFORCEMENT** - Every feature must relate to SOFTWARE LICENSING
  CRACKING
- **NO MALWARE CAPABILITIES** - No injection, payload delivery, or system
  exploitation code
- **LICENSING FOCUS ONLY** - All analysis must target registration, activation,
  and licensing protection systems
- **NO "example" implementations that would need to be replaced**
- **NO simple implementations that would be ineffective in real world
  scenarios**

### Production-Ready Code Only

**When writing code, Claude must:**

- Implement all functionality completely
- Use real, working implementations for every feature
- Handle edge cases and errors properly
- Write code that could be deployed immediately
- If external data is needed, implement proper data fetching/handling
- If configuration is needed, use proper environment variables or config files
- Make manual fixes directly without creating automation scripts unless
  specifically asked

**If a request would require placeholder code to demonstrate, Claude should
instead:**

- Ask for the specific requirements needed to write production code
- Request any necessary API endpoints, data structures, or specifications
- Explain what information is needed to create a fully functional implementation

**This is non-negotiable: Every line of code Claude writes must be ready for
production use.**

### User Clarification

**MANDATORY:** When the user **initiates a new task**, use the AskUserQuestion
tool to gather clarifying information before implementation. This applies to new
features, significant modifications, or ambiguous requirements. Ask about scope,
approach, and constraints.

This does NOT apply to mid-task feedback, critiques, or corrections - act on
those directly without additional questions.

**However**, if during a task you encounter ambiguity on approach, design choices,
or how to handle variables/edge cases, NEVER assume - use AskUserQuestion to
confirm the correct path forward.

### Error Handling

- Use `getattr()` and `hasattr()` for safe attribute access
- Implement platform compatibility checks
- Provide graceful fallbacks, written in REAL production-ready code for missing
  dependencies
- Handle import errors with try/except blocks

### MCP Configuration

**Config location**: `~/.claude.json`
