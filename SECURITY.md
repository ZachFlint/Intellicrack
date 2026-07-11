# Security Policy

## Automated Security Scanning

Intellicrack uses automated security scanning to identify and address potential
vulnerabilities:

### CodeQL Analysis

- **Languages Analyzed**: Actions, C/C++, JavaScript/TypeScript, Python, Rust
- **Scan Frequency**:
  - On every push to `main`
  - On all pull requests to `main`
  - Weekly scheduled scans (Saturdays at 04:28 UTC)

### Dependency Updates

Automated dependency updates via Dependabot:

- **GitHub Actions**: Weekly updates on Mondays
- **Rust (Cargo)**: Weekly updates on Mondays
- **Python (pip)**: Weekly updates on Mondays

## Reporting a Vulnerability

If you discover a security vulnerability in Intellicrack, please report it
responsibly:

1. **Do NOT** open a public issue
2. Contact the maintainers privately via GitHub Security Advisories
3. Provide detailed information about the vulnerability:
    - Type of vulnerability
    - Location in the codebase
    - Steps to reproduce
    - Potential impact
    - Suggested fix (if available)

## Security Best Practices

This project implements several security best practices:

- Automated security scanning with CodeQL
- Regular dependency updates via Dependabot
- Code review requirements for all pull requests
- Continuous integration with security checks
- Type checking and linting enforcement

## Scope

This security policy applies specifically to vulnerabilities in Intellicrack's
codebase. Intellicrack is a unified workspace that connects reverse-engineering
and binary-analysis tools with AI provider connectivity, and it is intended for
authorized testing and analysis in controlled environments only.
