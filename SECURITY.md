# Security Policy

## Supported Versions

Intellicrack is pre-1.0 and under active development. Security fixes land on
`main`; there are no maintained release branches.

| Version           | Supported   |
| ----------------- | ----------- |
| `main` (latest)   | Yes         |
| Tagged prereleases| Best effort |

## Reporting a Vulnerability

If you discover a security vulnerability in Intellicrack, please report it
responsibly:

1. **Do NOT** open a public issue.
2. Report privately through
   [GitHub Security Advisories](https://github.com/ZachFlint/Intellicrack/security/advisories/new).
3. Provide detailed information about the vulnerability:
    - Type of vulnerability
    - Location in the codebase
    - Steps to reproduce
    - Potential impact
    - Suggested fix (if available)

## Automated Security Scanning

- **Code scanning (CodeQL)** runs through GitHub's default setup on pushes and
  pull requests to `main`. There is no CodeQL workflow file in this repository;
  the configuration lives in the repository's Code security settings.
- **Qodana** static analysis runs via
  `.github/workflows/qodana_code_quality.yml`.
- **Bandit** Python security linting runs as part of
  `.github/workflows/ci.yml`. Findings are surfaced for review rather than
  enforced as a merge gate.
- **Secret scanning** is enabled on the repository, backed locally by a
  `detect-secrets` pre-commit hook and `.secrets.baseline`.

## Dependency Updates

Dependabot runs weekly (Mondays, 09:00 UTC) for:

- GitHub Actions
- Rust (Cargo) - `src/intellicrack-hexcore`
- Python (pip) - the generated `requirements.txt`
- JavaScript (npm)
- Docker - `docker/`

Python runtime dependencies are resolved by pixi and locked in `pixi.lock`,
which Dependabot cannot read directly. `requirements.txt` is generated from that
lockfile and is what Dependabot scans.

## Scope

This security policy applies specifically to vulnerabilities in Intellicrack's
own codebase. Intellicrack is a unified workspace that connects
reverse-engineering and binary-analysis tools with AI provider connectivity, and
it is intended for authorized testing and analysis in controlled environments
only.

Vulnerabilities in the third-party tools Intellicrack bridges to - Ghidra,
x64dbg, radare2/Cutter, Frida, QEMU and others - should be reported to their
respective upstream projects.
