#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Generate git commit messages using Google's Gemini API.

This script reads a git diff from stdin and generates a conventional commit
message using the Gemini API. It implements honest truncation thresholds
that reflect actual model capabilities.
"""

from __future__ import annotations

import os
import sys
from typing import Final

from google import genai
from google.genai import types
from google.genai.errors import ClientError


# Truncation thresholds (characters)
TRUNCATION_THRESHOLD: Final = 500_000  # ~125K tokens, 12.5% of 1M limit
FALLBACK_THRESHOLD: Final = 1_000_000  # ~250K tokens, 25% of 1M limit

# Prompt template
COMMIT_MESSAGE_PROMPT: Final = """Write a git commit message for these changes.

Rules:
- Conventional commit format: type: description
- Subject line under 72 characters
- Developer voice, technical and precise
- NO AI mentions, NO preamble, NO emojis
- Output ONLY the commit message
- For multi-area changes, add bullet points after a blank line

{truncation_notice}

{diff_input}
"""


def get_client() -> genai.Client:
    """Create and return a Gemini API client.

    Returns:
        genai.Client: Configured Gemini API client.

    Raises:
        SystemExit: If API key is not configured.
    """
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise SystemExit("GOOGLE_API_KEY environment variable not set")
    return genai.Client(api_key=api_key)


def generate_commit_message(diff_input: str, client: genai.Client) -> str:
    """Generate a commit message from the provided diff.

    Args:
        diff_input: The git diff content.
        client: The Gemini API client.

    Returns:
        str: Generated commit message.

    Raises:
        SystemExit: If generation fails.
    """
    truncation_notice = ""
    actual_input = diff_input

    # Determine truncation strategy
    diff_length = len(diff_input)
    if diff_length >= FALLBACK_THRESHOLD:
        # Too large even for truncation - use stat summary only
        print(
            f"Diff too large ({diff_length:,} chars), using file summary only",
            file=sys.stderr,
        )
        actual_input = diff_input.split("DIFF:\n")[1].split("\n", maxsplit=1)[0] if "DIFF:\n" in diff_input else diff_input[:10000]
        truncation_notice = "Note: Full diff exceeds practical limits. Message based on file change summary only.\n"
    elif diff_length >= TRUNCATION_THRESHOLD:
        # Truncate with notice
        actual_input = diff_input[:TRUNCATION_THRESHOLD]
        truncation_notice = f"Note: Diff truncated at {TRUNCATION_THRESHOLD:,} characters for practical processing. Message reflects visible changes.\n"

    # Build the prompt
    prompt = COMMIT_MESSAGE_PROMPT.format(
        truncation_notice=truncation_notice,
        diff_input=actual_input,
    )

    # Call the API
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=512,
            ),
        )

        if not response.text:
            raise SystemExit("No response text from API")

        return response.text.strip()

    except ClientError as e:
        raise SystemExit(f"API request failed: {e}") from e
    except Exception as e:
        raise SystemExit(f"Unexpected error: {e}") from e


def main() -> None:
    """Main entry point."""
    # Read diff from stdin
    diff_input = sys.stdin.read()

    if not diff_input.strip():
        raise SystemExit("No diff input provided")

    # Get client and generate message
    client = get_client()
    message = generate_commit_message(diff_input, client)

    # Output the commit message
    print(message)


if __name__ == "__main__":
    main()
