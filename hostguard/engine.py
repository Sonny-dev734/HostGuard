# hostguard/engine.py
from typing import Dict, Any

from hostguard.config import get_default_checks
from hostguard.checks.ssh import run as ssh_run
from hostguard.checks.firewall import run as firewall_run
from hostguard.checks.users import run as users_run
from hostguard.checks.services import run as services_run
from hostguard.checks.filesystem import run as filesystem_run


def run_all_checks() -> Dict[str, Dict[str, Any]]:
    """Run all security checks and return structured results.

    Every check:
    - runs locally,
    - only reads system state,
    - never modifies configuration or attacks anything,
    - returns a dict with:
        "check", "risk", "explanation", "score".

    If a subsystem is missing (e.g. no firewall), the check returns
    appropriate "error"/"warning" results instead of crashing.
    """
    results = {}
    enabled = get_default_checks()

    if enabled["ssh"]:
        try:
            results["ssh"] = ssh_run()
        except Exception as e:
            results["ssh"] = {
                "engine_error": {
                    "check": "ssh_engine",
                    "risk": "error",
                    "explanation": f"SSH check failed to run: {str(e)}",
                    "score": 0.1,
                }
            }

    if enabled["firewall"]:
        try:
            results["firewall"] = firewall_run()
        except Exception as e:
            results["firewall"] = {
                "engine_error": {
                    "check": "firewall_engine",
                    "risk": "error",
                    "explanation": f"Firewall check failed to run: {str(e)}",
                    "score": 0.1,
                }
            }

    if enabled["users"]:
        try:
            results["users"] = users_run()
        except Exception as e:
            results["users"] = {
                "engine_error": {
                    "check": "users_engine",
                    "risk": "error",
                    "explanation": f"Users check failed to run: {str(e)}",
                    "score": 0.1,
                }
            }

    if enabled["services"]:
        try:
            results["services"] = services_run()
        except Exception as e:
            results["services"] = {
                "engine_error": {
                    "check": "services_engine",
                    "risk": "error",
                    "explanation": f"Services check failed to run: {str(e)}",
                    "score": 0.1,
                }
            }

    if enabled["filesystem"]:
        try:
            results["filesystem"] = filesystem_run()
        except Exception as e:
            results["filesystem"] = {
                "engine_error": {
                    "check": "filesystem_engine",
                    "risk": "error",
                    "explanation": f"Filesystem check failed to run: {str(e)}",
                    "score": 0.1,
                }
            }

    return results




