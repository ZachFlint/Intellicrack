#!/usr/bin/env python3
"""Verify that no test files use mocks or fake data.
This script enforces the REAL DATA ONLY testing principle.
"""

import argparse
import os
import re
import sys
from pathlib import Path

# Patterns that indicate mock usage
MOCK_PATTERNS = [
    # Direct mock imports
    r"from\s+unittest\.mock\s+import",
    r"from\s+mock\s+import",
    r"import\s+unittest\.mock",
    r"import\s+mock",
    # Mock creation
    r"Mock\s*\(",
    r"MagicMock\s*\(",
    r"PropertyMock\s*\(",
    r"AsyncMock\s*\(",
    r"patch\s*\(",
    r"@patch",
    # Mock configuration
    r"return_value\s*=",
    r"side_effect\s*=",
    r"\.assert_called",
    r"\.assert_not_called",
    r"\.assert_any_call",
    r"\.call_count",
    # Fake data indicators
    r"fake_[a-zA-Z_]+\s*=",
    r"dummy_[a-zA-Z_]+\s*=",
    r"mock_[a-zA-Z_]+\s*=",
    r"placeholder_[a-zA-Z_]+\s*=",
    # Common test doubles
    r"class\s+Fake[A-Z]",
    r"class\s+Mock[A-Z]",
    r"class\s+Stub[A-Z]",
    r"class\s+Dummy[A-Z]",
    # Hardcoded test data
    r'["\']test123["\']',
    r'["\']example\.com["\']',
    r'["\']foo@bar\.com["\']',
    r'["\']placeholder["\']',
    r'["\']todo["\']',
    r'["\']fixme["\']',
]

# Files to exclude from checking
EXCLUDE_FILES = [
    "conftest.py",
    "__init__.py",
    "base_test.py",  # Base test class is allowed to mention mocks in validation
    "verify_no_mocks.py",  # This script contains patterns for detection
]

# Directories to exclude
EXCLUDE_DIRS = [
    "__pycache__",
    ".pytest_cache",
    "legacy_tests",
]


def find_mock_usage(file_path: Path) -> list[tuple[int, str, str]]:
    """Find all mock usage in a file.

    Returns list of (line_number, line_content, pattern_matched)
    """
    violations = []

    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()

        # Check if this is a validation script that legitimately checks for patterns
        is_validation_script = any(
            "validation" in str(file_path).lower() or "check" in str(file_path).lower() or "verify" in str(file_path).lower()
            for _ in [None]
        )

        for line_num, line in enumerate(lines, 1):
            # Skip comments that are just listing patterns to avoid
            if line.strip().startswith("#") and any(x in line.lower() for x in ["pattern", "avoid", "check", "detect"]):
                continue

            # Skip lines that are checking for these patterns (validation scripts)
            if is_validation_script and any(x in line for x in ["in line", "not in", "check", "detect", "validate"]):
                continue

            for pattern in MOCK_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    violations.append((line_num, line.strip(), pattern))
                    break
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

    return violations


def scan_test_directory(test_dir: Path) -> dict:
    """Scan entire test directory for mock usage.

    Returns dict of {file_path: [(line_num, line, pattern), ...]}
    """
    all_violations = {}

    for root, dirs, files in os.walk(test_dir):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file in files:
            if not file.endswith(".py"):
                continue

            if file in EXCLUDE_FILES:
                continue

            file_path = Path(root) / file
            if violations := find_mock_usage(file_path):
                all_violations[str(file_path)] = violations

    return all_violations


def classify_severity(pattern: str, line: str, file_path: str) -> str:
    """Classify violation severity."""
    # Critical violations - actual mock framework usage
    critical_patterns = ["from unittest.mock import", "from mock import", "import unittest.mock", "import mock"]

    # High violations - mock objects and assertions
    high_patterns = ["Mock(", "MagicMock(", "patch(", "@patch", ".assert_called"]

    if any(p in line for p in critical_patterns):
        return "CRITICAL"
    elif any(p in line for p in high_patterns):
        return "HIGH"
    elif "test123" in line or "placeholder" in line:
        return "MEDIUM"
    else:
        return "LOW"


def print_report(violations: dict, summary_only: bool = False) -> int:
    """Print violation report and return exit code."""
    if not violations:
        print("OK SUCCESS: No mock usage found in tests!")
        print("All tests appear to use REAL data as required.")
        return 0

    # Classify violations by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    critical_files = []

    for file_path, file_violations in violations.items():
        has_critical = False
        for _line_num, line, pattern in file_violations:
            severity = classify_severity(pattern, line, file_path)
            severity_counts[severity] += 1
            if severity == "CRITICAL":
                has_critical = True

        if has_critical:
            critical_files.append(file_path)

    # Print summary
    print("FAIL MOCK USAGE VIOLATIONS DETECTED")
    print("=" * 80)
    print(f"🔴 CRITICAL: {severity_counts['CRITICAL']} (Mock framework imports)")
    print(f"🟡 HIGH:     {severity_counts['HIGH']} (Mock objects/assertions)")
    print(f"🟠 MEDIUM:   {severity_counts['MEDIUM']} (Test data violations)")
    print(f"🔵 LOW:      {severity_counts['LOW']} (Other patterns)")
    print(f"\nTotal files affected: {len(violations)}")
    print("=" * 80)

    # Show critical violations first
    if critical_files and not summary_only:
        print("\n🚨 CRITICAL VIOLATIONS (Mock framework usage):")
        for file_path in critical_files[:10]:  # Show first 10
            file_violations = violations[file_path]
            print(f"\n📄 {file_path}")
            critical_lines = [
                (num, line, pat) for num, line, pat in file_violations if classify_severity(pat, line, file_path) == "CRITICAL"
            ]
            for line_num, line, _pattern in critical_lines[:3]:
                print(f"   Line {line_num}: {line}")

    print("\nWARNING  REMEDIATION REQUIRED:")
    print("1. Replace unittest.mock imports with real test data")
    print("2. Use fixtures from tests/fixtures/ directory")
    print("3. Implement real API responses for network tests")
    print("4. Use actual binary samples for exploitation tests")

    # Return appropriate exit code based on severity
    if severity_counts["CRITICAL"] > 0:
        return 2  # Critical violations
    elif severity_counts["HIGH"] > 0:
        return 1  # High violations
    else:
        return 0  # Only medium/low violations - warning only


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Verify that tests use real data instead of mocks")
    parser.add_argument("--summary", "-s", action="store_true", help="Show only summary, not detailed violations")
    parser.add_argument("--ci", action="store_true", help="CI mode: exit with code 2 for critical, 1 for high violations")
    parser.add_argument("--test-dir", type=Path, help="Override test directory path (default: auto-detect)")

    args = parser.parse_args()

    # Find test directory
    if args.test_dir:
        test_dir = args.test_dir
    else:
        script_dir = Path(__file__).parent
        test_dir = script_dir.parent  # tests/utils -> tests

    if not test_dir.exists():
        print(f"Error: Test directory not found at {test_dir}")
        return 1

    print(f" Scanning {test_dir} for mock usage...")
    if not args.summary:
        print("This may take a moment...\n")

    violations = scan_test_directory(test_dir)

    if args.ci:
        # In CI mode, return appropriate exit code
        return print_report(violations, summary_only=True)
    else:
        return print_report(violations, summary_only=args.summary)


if __name__ == "__main__":
    sys.exit(main())
