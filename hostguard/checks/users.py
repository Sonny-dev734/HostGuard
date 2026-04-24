# hostguard/checks/users.py
import os
import subprocess
from typing import Dict, Any


def get_users() -> Dict[str, Any]:
    """Parse /etc/passwd and return a dict of users."""
    try:
        with open("/etc/passwd", "r") as f:
            content = f.read()

        users = {}
        for line in content.splitlines():
            fields = line.strip().split(":")
            if len(fields) >= 7:
                uid = fields[2]
                shell = fields[6]
                username = fields[0]
                users[username] = {
                    "uid": int(uid),
                    "shell": shell,
                }
        return {"users_dict": users}
    except Exception as e:
        return {
            "engine_error": f"Cannot read /etc/passwd: {str(e)}"
        }


def check_root_user() -> Dict[str, Any]:
    """Check if root user is present and using a safe shell."""
    data = get_users()
    users = data.get("users_dict", {})

    root = users.get("root")
    if not root:
        return {
            "check": "root_user",
            "risk": "critical",
            "explanation": "No root user found; system is unusual or misconfigured.",
            "score": 0.1,
        }

    shell = root["shell"]
    if shell in ("/bin/sh", "/bin/bash", "/bin/dash"):
        return {
            "check": "root_user",
            "risk": "good",
            "explanation": "Root user has a normal shell.",
            "score": 0.9,
        }
    elif shell in ("/usr/sbin/nologin", "/bin/false"):
        return {
            "check": "root_user",
            "risk": "warning",
            "explanation": "Root user has nologin/false shell; may be unexpected.",
            "score": 0.7,
        }
    else:
        return {
            "check": "root_user",
            "risk": "warning",
            "explanation": f"Root user shell is {shell}; non‑standard.",
            "score": 0.6,
        }


def check_user_shells() -> Dict[str, Any]:
    """Check for suspicious shells."""
    data = get_users()
    users = data.get("users_dict", {})

    bad_shells = (
        "/bin/mail",
        "/bin/false",
        "/usr/sbin/nologin",
        "/bin:/bin",
        "/bin:/usr/bin",
    )

    count_bad = 0
    for username, info in users.items():
        shell = info["shell"].strip()
        if shell in bad_shells:
            count_bad += 1

    if count_bad == 0:
        return {
            "check": "user_shells",
            "risk": "good",
            "explanation": "No obviously suspicious shells found.",
            "score": 0.9,
        }
    else:
        return {
            "check": "user_shells",
            "risk": "warning",
            "explanation": f"{count_bad} accounts use suspicious shells.",
            "score": 0.5,
        }


def check_logged_in_users() -> Dict[str, Any]:
    """Check currently logged‑in users."""
    try:
        result = subprocess.run(
            ["who"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        lines = result.stdout.strip().splitlines()
        count = len(lines)

        if count == 0:
            return {
                "check": "logged_in_users",
                "risk": "info",
                "explanation": "No users currently logged in.",
                "score": 0.9,
            }
        elif count <= 3:
            return {
                "check": "logged_in_users",
                "risk": "good",
                "explanation": f"{count} user(s) logged in; normal for a desktop system.",
                "score": 0.8,
            }
        else:
            return {
                "check": "logged_in_users",
                "risk": "warning",
                "explanation": f"{count} users logged in; may be worth reviewing.",
                "score": 0.6,
            }
    except Exception as e:
        return {
            "check": "logged_in_users",
            "risk": "error",
            "explanation": f"Could not list logged‑in users: {str(e)}",
            "score": 0.4,
        }


def run() -> Dict[str, Dict[str, Any]]:
    """Run all user‑related checks.

    This is 100% local, read‑only:
    - reads /etc/passwd,
    - runs `who`,
    - never modifies users or sessions.

    Results are safe and explicit for security‑posture evaluation.
    """
    results = {}

    results["root_user"] = check_root_user()
    results["user_shells"] = check_user_shells()
    results["logged_in_users"] = check_logged_in_users()

    return results




