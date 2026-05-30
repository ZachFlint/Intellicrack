# Intellicrack

## Project Overview

**Intellicrack** is a unified desktop application for binary-analysis
workflows that brings multiple external tools and AI providers together in one
interface. Instead of acting as a standalone replacement for debuggers,
disassemblers, sandboxes, or model backends, it serves as the layer that
connects them, coordinates them, and makes them usable from a single GUI.

The purpose of Intellicrack is to reduce fragmentation in reverse-engineering
and analysis workflows. Users should be able to move between integrated tools,
inspect outputs, preserve relevant context, and send that context to connected
AI APIs without manually juggling disconnected windows, copy-pasting artifacts,
or rebuilding state between steps. The application should function as the
central workspace where tool output, user interaction, and AI-assisted
reasoning all meet.

At its core, Intellicrack should be understood as four connected layers. First,
it provides a GUI workspace where users manage projects, targets, sessions, and
outputs. Second, it exposes a bridge layer that integrates external tools and
internal modules through a consistent interface. Third, it includes AI provider
connectivity so users can configure local or remote models and route analysis
context into them. Fourth, it maintains orchestration and context management so
actions taken in one part of the application can inform work in another.

This means Intellicrack should be scoped around orchestration,
interoperability, and workflow continuity. Features should strengthen the
application's role as the central hub between analysis tools and AI systems.
The product should not be defined as a malware framework, exploit platform, or
covert operations tool, and it should also not be narrowly described as a
single-purpose licensing-cracking utility. If specialized binary-analysis use
cases are supported, they should be presented as workflows that the platform
can facilitate, not as the sole identity of the product.

In practical terms, Intellicrack should let users launch or connect supported
tools, capture and organize their outputs, maintain shared analysis state, and
use AI assistance directly inside that workflow. The GUI should make these
capabilities feel like one coherent application rather than a collection of
disconnected integrations. The defining value of Intellicrack is that it
unifies tools, context, and AI connectivity into a single operational surface.

## Tools

## USE THESE TOOLS

1. rg instead of grep
2. fd instead of find
3. tree is installed

## CRITICAL: SHELL USAGE

- **Always use `pwsh` (PowerShell 7) for PowerShell commands, NEVER
  `powershell.exe` (PowerShell 5)**
- When executing PowerShell commands, use `pwsh -Command '...'` or `pwsh -File ...`

## CRITICAL: VIRTUAL ENVIRONMENT USAGE

**Environment Usage:**

- **Pixi environment location**: `D:\Intellicrack\.pixi\envs\default`
- **Activation**: `pixi shell` or use `pixi run <command>`
- **AI assistant runs natively on Windows**

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
- **NEVER edit the basedpyright configuration** - The
  `[tool.basedpyright]` section in `pyproject.toml` must never be modified to
  weaken type checking strictness,
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

- **ALL CODE MUST BE WRITTEN FOR FULL COMPATIBILITY WITH WINDOWS PLATFORMS AS A
  PRIORITY.**
- **NO STUBS, MOCKS, OR PLACEHOLDERS** - ALL code must be FULLY FUNCTIONAL
- **NO TODO COMMENTS** - Implement REAL functionality immediately
- **NEVER delete method bindings** - CREATE MISSING FUNCTIONS instead
- **MAINTAIN FUNCTIONALITY** - Never sacrifice features for "cleaner" code
- **SCOPE ENFORCEMENT** - Every feature must strengthen Intellicrack's role as
  a unified GUI bridge for tools, workflows, and AI provider connectivity
- **NO MALWARE CAPABILITIES** - No payload delivery, persistence, credential
  theft, destructive behavior, or system exploitation code
- **INTEGRATION FOCUS** - Features should improve orchestration,
  interoperability, context management, or AI-assisted workflow support
- **NO "example" implementations that would need to be replaced**
- **NO simple implementations that would be ineffective in real world
  scenarios**

### Production-Ready Code Only

**When writing code, the AI assistant must:**

- Implement all functionality completely
- Use real, working implementations for every feature
- Handle edge cases and errors properly
- Write code that could be deployed immediately
- If external data is needed, implement proper data fetching/handling
- If configuration is needed, use proper environment variables or config files
- Make manual fixes directly without creating automation scripts unless
  specifically asked

**If a request would require placeholder code to demonstrate, the AI assistant should
instead:**

- Ask for the specific requirements needed to write production code
- Request any necessary API endpoints, data structures, or specifications
- Explain what information is needed to create a fully functional implementation

**This is non-negotiable: Every line of code the AI assistant writes must
be ready for production use.**

### User Clarification

**MANDATORY:** When the user **initiates a new task**, use the AskUserQuestion
tool to gather clarifying information before implementation. This applies to new
features, significant modifications, or ambiguous requirements. Ask about scope,
approach, and constraints.

This does NOT apply to mid-task feedback, critiques, or corrections - act on
those directly without additional questions.

**However**, if during a task you encounter ambiguity on approach, design choices,
or how to handle variables/edge cases, NEVER assume - stop and ask the user a
question to confirm the correct path forward.

### Error Handling

- Use `getattr()` and `hasattr()` for safe attribute access
- Implement platform compatibility checks
- Provide graceful fallbacks, written in REAL production-ready code for missing
  dependencies
- Handle import errors with try/except blocks

### MCP Configuration

**Config location**: `~/.mcp.json`
