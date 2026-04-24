# hostguard/config.py
import os
from typing import Dict


# --- Directory helpers ---

def get_project_dir() -> str:
    """Return the absolute path of the HostGuard project."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --- Default checks ---

def get_default_checks() -> Dict[str, bool]:
    """Return a dictionary of checks that are enabled by default."""
    return {
        "ssh": True,
        "firewall": True,
        "users": True,
        "services": True,
        "filesystem": True,
    }


# --- Risk / scoring thresholds ---

def get_thresholds() -> Dict[str, float]:
    """Return risk thresholds for overall score interpretation."""
    return {
        # Overall score interpretation
        "perfect_score": 0.9,  # 0.9–1.0 → GOOD
        "warning_score": 0.6,  # 0.6–0.9 → WARNING
        "critical_score": 0.3, # 0.0–0.3 → CRITICAL

        # Fraction of checks that can fail before warning
        "fail_ratio_warning": 0.30,
        "fail_ratio_critical": 0.60,
    }

# --- Path helpers (safe, local, no network) ---

def get_logs_dir() -> str:
    """Return a local logs directory under the project."""
    logs_dir = os.path.join(get_project_dir(), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    return logs_dir


