#!/usr/bin/env python3
# main.py
import sys
import traceback

from hostguard.engine import run_all_checks
from hostguard.reporter import print_detailed_report, compute_score


def main() -> None:
    """Run the HostGuard security audit."""
    print("Starting HostGuard security posture audit...")
    print("(Local, read‑only; no network traffic, no attacks.)")
    print()

    try:
        results = run_all_checks()
    except Exception as e:
        print(f"[FATAL] HostGuard engine failed: {e}")
        traceback.print_exc()
        sys.exit(1)

    score = compute_score(results)
    print_detailed_report(results, score)


if __name__ == "__main__":
    main()




