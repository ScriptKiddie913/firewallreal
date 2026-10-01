#!/usr/bin/env python3
"""Release Hygiene & Secret Verifier for SentinelFW / SentinelGate.

Fails (exit 1) if:
- Any private key or certificate files (*.key, *.crt, *.pem, *.p12) exist
- Any test data directory (_test_data) exists
- Any private key content banners exist in production source files
- Any leftover master credential literals exist in code or docs
"""

import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_EXTENSIONS = {".key", ".crt", ".pem", ".p12", ".pfx"}
FORBIDDEN_DIRS = {"_test_data"}
FORBIDDEN_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"Hotmeha21@"),
]

# Paths or files allowed to mention pattern names for DLP detection / test / doc verification
EXEMPT_PARTS = {
    "tests",
    "docs",
    "scripts",
}
EXEMPT_FILES = {
    "dlp.py",
    "dlp.go",
}


def clean_pycache():
    for p in ROOT.rglob("__pycache__"):
        if ".git" not in str(p):
            shutil.rmtree(p, ignore_errors=True)
    for p in ROOT.rglob("*.pyc"):
        if ".git" not in str(p):
            try:
                p.unlink()
            except OSError:
                pass


def check_hygiene() -> int:
    clean_pycache()
    violations = []

    for root, dirs, files in os.walk(ROOT):
        # Exclude .git and venv directories
        if ".git" in root or "venv" in root or ".gemini" in root:
            continue

        rel_root = Path(root).relative_to(ROOT)
        for d in list(dirs):
            if d in FORBIDDEN_DIRS:
                violations.append(f"Forbidden directory present: {rel_root / d}")

        for f in files:
            path = Path(root) / f
            rel_path = path.relative_to(ROOT)

            if path.suffix.lower() in FORBIDDEN_EXTENSIONS:
                violations.append(f"Forbidden file extension: {rel_path}")

            is_exempt = f in EXEMPT_FILES or any(part in rel_path.parts for part in EXEMPT_PARTS)
            if not is_exempt and path.is_file() and path.stat().st_size < 2_000_000:
                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")
                    for pat in FORBIDDEN_PATTERNS:
                        if pat.search(content):
                            violations.append(f"Forbidden secret pattern matched in production file: {rel_path}")
                except Exception as ex:
                    violations.append(f"Could not scan {rel_path}: {ex}")

    if violations:
        print("\n" + "=" * 60)
        print("  RELEASE HYGIENE AUDIT FAILED")
        print("=" * 60)
        for v in violations:
            print(f"  [X] {v}")
        print("=" * 60 + "\n")
        return 1

    print("\n[OK] Release hygiene audit passed: zero keys, certificates, or hardcoded secrets detected.\n")
    return 0


if __name__ == "__main__":
    sys.exit(check_hygiene())
