#!/usr/bin/env python3
"""Run every standalone regression script and summarize results."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent


def discover():
    files = []
    for sub in ("LLM", "HUMAN"):
        files.extend(sorted((TESTS / sub).glob("*.py")))
    return files


def main():
    files = discover()
    failed = []
    for script in files:
        print(f"\n=== SUITE: {script.relative_to(ROOT)} ===")
        rc = subprocess.run([sys.executable, "-I", str(script)], cwd=str(ROOT)).returncode
        if rc != 0:
            failed.append(script.relative_to(ROOT))
    total = len(files)
    passed = total - len(failed)
    print(f"\nSUMMARY: {passed}/{total} suites passed")
    for p in failed:
        print(f"  FAILED: {p}")
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
