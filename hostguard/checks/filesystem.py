# hostguard/checks/filesystem.py
import os
import stat
from typing import Dict, Any


SENSITIVE_DIRS = ["/etc", "/tmp", "/var", "/home", "/root"]
RISKY_PATHS = ["/etc/shadow", "/etc/gshadow", "/root/.ssh/id_rsa"]


def check_risky_paths_exist() -> Dict[str, Any]:
    """Check if obviously risky files exist and are readable."""
    for path in RISKY_PATHS:
        if not os.path.exists(path):
            continue

        try:
            st = os.stat(path)
            mode = st.st_mode

            if not (stat.S_ISREG(mode) and stat.S_IMODE(mode) & 0o700 == 0o600):
                return {
                    "check": "risky_file_permissions",
                    "risk": "critical",
                    "explanation": f"{path} exists and has unsafe permissions.",
                    "score": 0.0,
                }
        except Exception:
            pass

    return {
        "check": "risky_file_permissions",
        "risk": "good",
        "explanation": "No obviously risky unguarded files in /etc/.ssh/.shadow found.",
        "score": 0.9,
    }


def check_dir_writability(path: str, max_world_writable: int = 5) -> Dict[str, Any]:
    """Check for world‑writable files in a directory."""
    if not os.path.isdir(path):
        return {
            "check": f"world_writable_files_{os.path.basename(path)}",
            "risk": "error",
            "explanation": f"Directory {path} not found or not a directory.",
            "score": 0.3,
        }

    world_writable = 0

    for root, dirs, files in os.walk(path, followlinks=False, topdown=False):
        for name in dirs + files:
            full = os.path.join(root, name)
            if os.path.islink(full):
                continue
            if not os.path.isfile(full):
                continue

            try:
                st = os.stat(full)
                mode = st.st_mode
                if (mode & 0o002) and (mode & 0o020) == 0:
                    world_writable += 1
            except Exception:
                pass

            if world_writable > 100:  # cap to avoid huge loops
                break

    if world_writable == 0:
        return {
            "check": f"world_writable_files_{os.path.basename(path)}",
            "risk": "good",
            "explanation": f"No world‑writable files in {path}.",
            "score": 0.9,
        }
    elif world_writable <= max_world_writable:
        return {
            "check": f"world_writable_files_{os.path.basename(path)}",
            "risk": "warning",
            "explanation": f"{world_writable} world‑writable files in {path}; review.",
            "score": 0.6,
        }
    else:
        return {
            "check": f"world_writable_files_{os.path.basename(path)}",
            "risk": "critical",
            "explanation": f"{world_writable} world‑writable files in {path}; very risky.",
            "score": 0.2,
        }


def run() -> Dict[str, Dict[str, Any]]:
    """Run filesystem‑related checks.

    This is 100% local, read‑only:
    - walks certain directories,
    - checks file permissions,
    - never modifies files or directories.

    Results help detect overly permissive filesystem configuration.
    """
    results = {}

    results["risky_paths_exist"] = check_risky_paths_exist()

    for d in SENSITIVE_DIRS:
        if os.path.isdir(d):
            results[d.replace("/", "_").strip("_")] = check_dir_writability(d)

    return results



