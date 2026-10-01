#!/usr/bin/env python3
"""Automated, reproducible release packager for SentinelFW / SentinelGate.

Enforces hygiene checks, removes caches, and creates clean .tar.gz and .zip archives
in the dist/ directory.
"""

import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

EXCLUDE_PATTERNS = {
    ".git",
    ".github",
    ".pytest_cache",
    "__pycache__",
    "_test_data",
    "dist",
    ".coverage",
}


def main():
    print("[*] Running pre-packaging release hygiene audit...")
    hygiene_script = ROOT / "scripts" / "check_release_hygiene.py"
    res = subprocess.run([sys.executable, str(hygiene_script)], cwd=str(ROOT))
    if res.returncode != 0:
        print("[!] Pre-packaging hygiene audit failed! Aborting release packaging.")
        sys.exit(1)

    # Read version
    version = "4.0.0"
    for line in (ROOT / "sentinelfw" / "common.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("VERSION ="):
            version = line.split("=")[1].strip().strip('"').strip("'")
            break

    print(f"[*] Packaging SentinelGate OS / SentinelFW v{version}...")
    DIST.mkdir(exist_ok=True)

    base_name = f"sentinelfw-{version}"
    tar_path = DIST / f"{base_name}.tar.gz"
    zip_path = DIST / f"{base_name}.zip"

    # Filter function
    def is_included(p: Path) -> bool:
        for part in p.parts:
            if part in EXCLUDE_PATTERNS:
                return False
            if part.endswith(".pyc") or part.endswith(".key") or part.endswith(".crt"):
                return False
        return True

    # 1. Build .tar.gz
    print(f"[*] Creating {tar_path.name}...")
    with tarfile.open(tar_path, "w:gz") as tar:
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_PATTERNS]
            for f in files:
                full_path = Path(root) / f
                rel_path = full_path.relative_to(ROOT)
                if is_included(rel_path):
                    arcname = Path(base_name) / rel_path
                    tar.add(full_path, arcname=str(arcname))

    # 2. Build .zip
    print(f"[*] Creating {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_PATTERNS]
            for f in files:
                full_path = Path(root) / f
                rel_path = full_path.relative_to(ROOT)
                if is_included(rel_path):
                    arcname = Path(base_name) / rel_path
                    zipf.write(full_path, arcname=str(arcname))

    print(f"\n[OK] Release packaging completed successfully!")
    print(f"  - {tar_path} ({tar_path.stat().st_size:,} bytes)")
    print(f"  - {zip_path} ({zip_path.stat().st_size:,} bytes)\n")


if __name__ == "__main__":
    main()
