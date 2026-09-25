from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {
    ".git",
    ".venv",
    "data",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
PATTERNS = {
    "OpenAI-style key": re.compile(
        r"\bsk-[A-Za-z0-9_-]{20,}\b"
    ),
    "GitHub token": re.compile(
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"
    ),
    "AWS access key": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),
    "private key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
}


def main() -> int:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if (
            not path.is_file()
            or any(part in SKIP_DIRS for part in path.parts)
        ):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(
                    f"{path.relative_to(ROOT)}: {name}"
                )

    if findings:
        print("Potential secrets detected:")
        for finding in findings:
            print(f"- {finding}")
        return 1

    print("No high-confidence secret patterns detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
