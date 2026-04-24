# hostguard/checks/ssh.py
import os
from typing import Dict, Any


SSH_CONFIG = "/etc/ssh/sshd_config"


def check_ssh_config_file_exists() -> Dict[str, Any]:
    """Check if SSH config file exists on the system."""
    if not os.path.exists(SSH_CONFIG):
        return {
            "check": "ssh_config_file_exists",
            "risk": "error",
            "explanation": "/etc/ssh/sshd_config not found; cannot audit SSH settings.",
            "score": 0.1,
        }
    else:
        return {
            "check": "ssh_config_file_exists",
            "risk": "good",
            "explanation": "/etc/ssh/sshd_config found; SSH settings are auditable.",
            "score": 1.0,
        }


def check_ssh_port() -> Dict[str, Any]:
    """Check if SSH port is non‑default (safer)."""
    if not os.path.exists(SSH_CONFIG):
        return {
            "check": "ssh_port",
            "risk": "error",
            "explanation": "SSH config file not found; cannot check SSH port.",
            "score": 0.2,
        }

    with open(SSH_CONFIG, "r") as f:
        content = f.read()

    default_port = 22
    port = default_port  # assume default if no explicit line
    found = False

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("Port "):
            try:
                found = True
                port = int(line.split()[1])
            except (IndexError, ValueError):
                # Parsing failed; keep default
                pass
            break

    if not found:
        return {
            "check": "ssh_port",
            "risk": "warning",
            "explanation": "Port line missing in SSH config; default port 22 assumed.",
            "score": 0.4,
        }

    if port == default_port:
        return {
            "check": "ssh_port",
            "risk": "warning",
            "explanation": f"SSH port is {port}; using default port 22 is risky.",
            "score": 0.4,
        }
    else:
        return {
            "check": "ssh_port",
            "risk": "good",
            "explanation": f"SSH port is {port}, which is safer than default 22.",
            "score": 0.9,
        }


def check_root_login() -> Dict[str, Any]:
    """Check if PermitRootLogin is disabled or safely configured."""
    if not os.path.exists(SSH_CONFIG):
        return {
            "check": "ssh_root_login",
            "risk": "error",
            "explanation": "SSH config file not found; cannot check root login.",
            "score": 0.2,
        }

    with open(SSH_CONFIG, "r") as f:
        content = f.read()

    expected_values = ("yes", "without-password", "no", "forced-commands-only")
    default_value = "yes"  # default behavior of sshd if missing
    value = default_value
    found = False

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("PermitRootLogin "):
            try:
                found = True
                value = line.split()[1].lower()
            except IndexError:
                pass
            break

    if not found:
        return {
            "check": "ssh_root_login",
            "risk": "warning",
            "explanation": "PermitRootLogin line missing; default likely allowed.",
            "score": 0.3,
        }

    if value == "yes":
        return {
            "check": "ssh_root_login",
            "risk": "critical",
            "explanation": "PermitRootLogin is 'yes'; allowing root login is very risky.",
            "score": 0.1,
        }
    elif value == "without-password":
        return {
            "check": "ssh_root_login",
            "risk": "warning",
            "explanation": "PermitRootLogin is 'without-password'; root login possible with key authentication.",
            "score": 0.4,
        }
    elif value in ("no", "forced-commands-only"):
        return {
            "check": "ssh_root_login",
            "risk": "good",
            "explanation": f"PermitRootLogin is '{value}'; root login is disabled or restricted.",
            "score": 0.9,
        }
    else:
        return {
            "check": "ssh_root_login",
            "risk": "error",
            "explanation": f"PermitRootLogin value '{value}' is not standard.",
            "score": 0.5,
        }


def check_password_authentication() -> Dict[str, Any]:
    """Check if PasswordAuthentication is disabled (safer)."""
    if not os.path.exists(SSH_CONFIG):
        return {
            "check": "ssh_password_auth",
            "risk": "error",
            "explanation": "SSH config file not found; cannot check password authentication.",
            "score": 0.3,
        }

    with open(SSH_CONFIG, "r") as f:
        content = f.read()

    expected_values = ("yes", "no")
    default_value = "yes"  # default behavior of sshd
    value = default_value
    found = False

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("PasswordAuthentication "):
            try:
                found = True
                value = line.split()[1].lower()
            except IndexError:
                pass
            break

    if not found:
        return {
            "check": "ssh_password_auth",
            "risk": "warning",
            "explanation": "PasswordAuthentication line missing; default password auth assumed.",
            "score": 0.4,
        }

    if value == "yes":
        return {
            "check": "ssh_password_auth",
            "risk": "warning",
            "explanation": "PasswordAuthentication is 'yes'; weaker than key‑only.",
            "score": 0.5,
        }
    elif value == "no":
        return {
            "check": "ssh_password_auth",
            "risk": "good",
            "explanation": "PasswordAuthentication is disabled; only key authentication allowed.",
            "score": 0.9,
        }
    else:
        return {
            "check": "ssh_password_auth",
            "risk": "error",
            "explanation": f"PasswordAuthentication value '{value}' is not standard.",
            "score": 0.6,
        }


def run() -> Dict[str, Dict[str, Any]]:
    """Run all SSH checks and return their results.

    Each result is a dictionary with:
    - check: name of the check,
    - risk: "good", "warning", "critical", "error",
    - explanation: human‑readable text,
    - score: float between 0.0 and 1.0.

    This check is 100% local, read‑only, and safe.
    """
    results = {}
    results["ssh_config_file_exists"] = check_ssh_config_file_exists()
    results["ssh_port"] = check_ssh_port()
    results["ssh_root_login"] = check_root_login()
    results["ssh_password_auth"] = check_password_authentication()
    return results



