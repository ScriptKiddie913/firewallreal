#!/usr/bin/env python3
"""
SentinelGate & SentinelFW 3.0: Phase P0 Verification & Baseline Benchmark Suite
Validates workspace structure, documentation, configuration files, and baseline tests.
"""

import os
import sys
import time
import unittest
import shutil
import argparse

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def check_file(rel_path: str, min_size: int = 50) -> bool:
    full_path = os.path.join(REPO_ROOT, rel_path)
    if not os.path.exists(full_path):
        print(f"[-] MISSING: {rel_path}")
        return False
    size = os.path.getsize(full_path)
    if size < min_size:
        print(f"[-] TOO SMALL ({size} bytes): {rel_path}")
        return False
    print(f"[+] FOUND: {rel_path} ({size} bytes)")
    return True

def verify_structure() -> bool:
    print("\n--- [1] Verifying Monorepo Structure & Key Artifacts ---")
    required_files = [
        "docs/architecture.md",
        "docs/threat_model.md",
        "go.mod",
        "Makefile",
        ".github/workflows/ci.yml",
        "lab/topologies/gateway_lab.clab.yml",
        "lab/setup_netns_lab.sh",
        "README.md",
        "config.example.json",
        "sfwctl.py"
    ]
    all_ok = True
    for f in required_files:
        if not check_file(f):
            all_ok = False
    return all_ok

def run_baseline_tests() -> bool:
    print("\n--- [2] Running Existing SentinelFW Test Suites ---")
    tests_dir = os.path.join(REPO_ROOT, "tests")
    loader = unittest.TestLoader()
    suite = loader.discover(tests_dir, pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=1)
    start_t = time.perf_counter()
    result = runner.run(suite)
    elapsed = time.perf_counter() - start_t
    print(f"[+] Test run completed in {elapsed:.3f}s. Tests run: {result.testsRun}, Errors: {len(result.errors)}, Failures: {len(result.failures)}")
    return result.wasSuccessful()

def benchmark_baseline_overhead():
    print("\n--- [3] Baseline Heuristic & Rule Evaluation Benchmark ---")
    sys.path.insert(0, REPO_ROOT)
    from sentinelfw.backends import WinBackend, NftBackend
    from sentinelfw.engine import Engine
    from sentinelfw.common import IS_WIN
    from sentinelfw.config import Store
    import tempfile

    temp_dir = tempfile.mkdtemp(prefix="sg-p0-bench-")
    old_home = os.environ.get("SENTINELFW_HOME")
    os.environ["SENTINELFW_HOME"] = temp_dir
    try:
        engine = Engine()

        # Benchmark 20,000 IP ban lookups and safety guard evaluations
        t0 = time.perf_counter()
        iterations = 20000
        for i in range(iterations):
            engine.guard.protected(f"192.168.1.{(i % 254) + 1}")
        eval_time = time.perf_counter() - t0
        eval_rate = iterations / eval_time
        print(f"[+] Rule / Safety Evaluation: {iterations:,} checks in {eval_time:.4f}s ({eval_rate:,.0f} ops/sec)")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        if old_home is not None:
            os.environ["SENTINELFW_HOME"] = old_home
        elif "SENTINELFW_HOME" in os.environ:
            del os.environ["SENTINELFW_HOME"]

def parse_args():
    parser = argparse.ArgumentParser(description="Run Phase P0 verification checks.")
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip Python test suite discovery/execution.",
    )
    parser.add_argument(
        "--skip-benchmark",
        action="store_true",
        help="Skip baseline benchmark execution.",
    )
    return parser.parse_args()

def main():
    args = parse_args()
    print("==================================================================")
    print(" SentinelGate & SentinelFW 3.0: Phase P0 Automated Verification ")
    print("==================================================================")
    
    struct_ok = verify_structure()
    tests_ok = True
    if args.skip_tests:
        print("\n--- [2] Skipping Baseline Test Suites (flag: --skip-tests) ---")
    else:
        tests_ok = run_baseline_tests()

    if args.skip_benchmark:
        print("\n--- [3] Skipping Baseline Benchmark (flag: --skip-benchmark) ---")
    else:
        benchmark_baseline_overhead()

    print("\n------------------------------------------------------------------")
    if struct_ok and tests_ok:
        print("[SUCCESS] Phase P0 Verification Passed with Zero Errors!")
        return 0
    else:
        print("[FAILURE] Phase P0 Verification Failed. Inspect logs above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
