# hostguard/checks/firewall.py
import os
import subprocess
from typing import Dict, Any


def has_ufw() -> bool:
    """Check if ufw is installed."""
    try:
        result = subprocess.run(
            ["which", "ufw"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def has_iptables() -> bool:
    """Check if iptables exists."""
    try:
        result = subprocess.run(
            ["which", "iptables"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def has_nftables() -> bool:
    """Check if nftables exists."""
    try:
        result = subprocess.run(
            ["which", "nft"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def check_ufw_status() -> Dict[str, Any]:
    """Check if ufw is enabled and has sane default policies."""
    if not has_ufw():
        return {
            "check": "ufw_enabled",
            "risk": "info",
            "explanation": "ufw not installed; no ufw status to check.",
            "score": 0.8,
        }

    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        output = result.stdout.strip()

        # The status line is usually the first line
        first_line = output.strip().splitlines()[0].lower()

        # Normalize whitespace and common formats
        normalized = " ".join(first_line.split()).strip()

        # Common patterns for "active" (in any language)
        # English: "Status: active"
        # French: "Status: actif"
        # The STATUS is always the keyword
        if normalized.startswith("status:") and "active" in normalized:
            return {
                "check": "ufw_enabled",
                "risk": "good",
                "explanation": "ufw is active and running.",
                "score": 0.9,
            }
        elif normalized.startswith("status:") and "inactive" in normalized:
            return {
                "check": "ufw_enabled",
                "risk": "critical",
                "explanation": "ufw is not active; no firewall enforced.",
                "score": 0.1,
            }
        else:
            # If the format is unexpectedly different
            return {
                "check": "ufw_enabled",
                "risk": "warning",
                "explanation": f"ufw status output unrecognized: '{normalized}'. Please check manually.",
                "score": 0.4,
            }

    except Exception as e:
        return {
            "check": "ufw_enabled",
            "risk": "error",
            "explanation": f"Could not query ufw status: {str(e)}",
            "score": 0.3,
        }
def check_iptables_exists() -> Dict[str, Any]:
    """Check if iptables exists on the system."""
    if not has_iptables():
        return {
            "check": "iptables_exists",
            "risk": "info",
            "explanation": "iptables not installed.",
            "score": 0.9,
        }

    return {
        "check": "iptables_exists",
        "risk": "good",
        "explanation": "iptables exists; firewall rules can be configured.",
        "score": 0.9,
    }


def check_iptables_rules() -> Dict[str, Any]:
    """Check if there are non‑trivial iptables rules."""
    if not has_iptables():
        return {
            "check": "iptables_rules",
            "risk": "error",
            "explanation": "iptables not installed; cannot list rules.",
            "score": 0.2,
        }

    try:
        result = subprocess.run(
            ["sudo", "iptables", "-L", "-n"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        output = result.stdout.strip()

        lines = output.splitlines()
        # Very basic: check if there are non‑default rules
        if len(lines) <= 3:
            return {
                "check": "iptables_rules",
                "risk": "warning",
                "explanation": "iptables has almost no rules; minimal firewall.",
                "score": 0.4,
            }

        # If there are rules, assume they are non‑trivial
        return {
            "check": "iptables_rules",
            "risk": "good",
            "explanation": "iptables has non‑trivial rules defined.",
            "score": 0.8,
        }

    except Exception as e:
        return {
            "check": "iptables_rules",
            "risk": "error",
            "explanation": f"Could not list iptables rules: {str(e)}",
            "score": 0.3,
        }


def check_nftables_exists() -> Dict[str, Any]:
    """Check if nftables exists on the system."""
    if not has_nftables():
        return {
            "check": "nftables_exists",
            "risk": "info",
            "explanation": "nftables not installed.",
            "score": 0.9,
        }

    return {
        "check": "nftables_exists",
        "risk": "good",
        "explanation": "nftables exists; can define firewall rules.",
        "score": 0.9,
    }


def check_nftables_rules() -> Dict[str, Any]:
    """Check if there are nftables rules."""
    if not has_nftables():
        return {
            "check": "nftables_rules",
            "risk": "error",
            "explanation": "nftables not installed; cannot list rules.",
            "score": 0.2,
        }

    try:
        result = subprocess.run(
            ["sudo", "nft", "list", "ruleset"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        output = result.stdout.strip()

        lines = output.splitlines()
        if len(lines) == 0:
            return {
                "check": "nftables_rules",
                "risk": "warning",
                "explanation": "nftables ruleset is empty.",
                "score": 0.4,
            }

        return {
            "check": "nftables_rules",
            "risk": "good",
            "explanation": "nftables ruleset has defined rules.",
            "score": 0.8,
        }

    except Exception as e:
        return {
            "check": "nftables_rules",
            "risk": "error",
            "explanation": f"Could not list nftables rules: {str(e)}",
            "score": 0.3,
        }


def run() -> Dict[str, Dict[str, Any]]:
    """Run all firewall‑related checks and return their results.

    This is 100% local, read‑only:
    - runs `ufw`, `iptables`, `nftables` commands with `sudo` (if available),
    - only reads current state,
    - never modifies rules or config.

    If sudo is not available or commands fail, it returns appropriate error/warning results.
    """
    results = {}

    results["ufw_enabled"] = check_ufw_status()

    results["iptables_exists"] = check_iptables_exists()
    results["iptables_rules"] = check_iptables_rules()

    results["nftables_exists"] = check_nftables_exists()
    results["nftables_rules"] = check_nftables_rules()

    return results


