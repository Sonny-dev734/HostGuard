# hostguard/reporter.py
from typing import Dict, Any
from hostguard.config import get_thresholds


def compute_score(results: Dict[str, Dict[str, Any]]) -> float:
    """Compute a global security score from all checks."""
    total_score = 0.0
    count = 0

    for cat, checks in results.items():
        if isinstance(checks, dict):
            for check_id, data in checks.items():
                if isinstance(data, dict) and "score" in data:
                    total_score += data["score"]
                    count += 1

    if count == 0:
        return 0.0
    return total_score / count


def format_risk_label(risk: str) -> str:
    """Convert risk to standardized label (no emojis)."""
    mapping = {
        "good": "GOOD",
        "warning": "WARNING",
        "critical": "CRITICAL",
        "error": "ERROR",
        "unknown": "UNKNOWN",
    }
    return mapping.get(risk.lower(), "UNKNOWN")


def print_detailed_report(
    results: Dict[str, Dict[str, Any]], score: float
) -> None:
    """Print a structured, human‑readable report."""
    print("=== HostGuard – Linux Host Security Posture Audit ===")
    print()
    print("All checks are read‑only and local; no network traffic, no attacks.")
    print()

    for cat, checks in results.items():
        if not isinstance(checks, dict):
            continue

        print(f"Category: {cat.upper()}")
        print("-" * 50)

        for check_id, data in checks.items():
            if not isinstance(data, dict):
                continue

            c = data.get("check", check_id)
            risk = data.get("risk", "unknown")
            expl = data.get("explanation", "No explanation.")
            score_value = data.get("score", 0.0)

            risk_label = format_risk_label(risk)

            print(f"  Check: {c}")
            print(f"  Risk: {risk_label}")
            print(f"  Explanation: {expl}")
            print(f"  Score value: {score_value:.3f}")
            print()

        print()

    thresholds = get_thresholds()
    perfect = thresholds["perfect_score"]
    warning = thresholds["warning_score"]
    critical = thresholds["critical_score"]

    print("=== Overall Security Score ===")
    print(f"Score: {score:.3f} (1.0 = perfect, 0.0 = very risky)")

    if score >= perfect:
        status = "GOOD – security posture is strong."
    elif score >= warning:
        status = "WARNING – several issues should be reviewed."
    elif score >= critical:
        status = "CRITICAL – many security issues present; review immediately."
    else:
        status = "SEVERE – posture is very weak; urgent action recommended."

    print(f"Status: {status}")
    print()
    print("This tool runs only locally and does not attack or scan other systems.")



