"""Command extraction from LLM output.

LLMs often wrap commands in markdown code blocks or add explanatory text.
``extract_command`` strips that away and returns the raw shell command.
"""

from __future__ import annotations

import re


def extract_command(text: str) -> str:
    """Extract a shell command from free-form LLM output.

    Handles common patterns:
    1. Bare command (no wrapping)
    2. Markdown code block (```bash ... ``` or ``` ... ```)
    3. Single backtick wrapping (`command`)
    4. "Command:" prefix
    5. Multi-line output -- takes the first non-empty, non-comment line

    Args:
        text: Raw LLM output text.

    Returns:
        Cleaned shell command string. Returns original text stripped
        if no pattern matches.
    """
    if not text:
        return ""

    stripped = text.strip()

    # Pattern 1: Markdown fenced code block (```bash ... ``` or ``` ... ```)
    fenced = re.search(
        r"```(?:bash|sh|shell|zsh)?\s*\n(.*?)```",
        stripped,
        re.DOTALL,
    )
    if fenced:
        # Take the first non-empty line from the code block
        lines = [
            ln.strip()
            for ln in fenced.group(1).strip().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if lines:
            return lines[0]

    # Pattern 2: Single backtick wrapping
    backtick = re.search(r"`([^`]+)`", stripped)
    if backtick:
        candidate = backtick.group(1).strip()
        # Only use if it looks like a command (not prose with backticks)
        if candidate and not candidate[0].isupper():
            return candidate

    # Pattern 3: "Command:" or "Run:" prefix
    prefix_match = re.search(
        r"(?:command|run|execute|cmd)\s*:\s*(.+)",
        stripped,
        re.IGNORECASE,
    )
    if prefix_match:
        return prefix_match.group(1).strip().strip("`")

    # Pattern 4: Multi-line -- take first non-empty, non-comment line
    lines = [
        ln.strip()
        for ln in stripped.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if lines:
        # If the first line looks like prose (starts with uppercase and has
        # many words), try subsequent lines
        first = lines[0]
        if len(lines) > 1 and first[0].isupper() and len(first.split()) > 5:
            # Probably explanation text; try to find the actual command
            for ln in lines[1:]:
                if not ln[0].isupper() or ln.startswith(("nmap", "curl", "ssh")):
                    return ln.strip("`").strip()

        return first

    return stripped
