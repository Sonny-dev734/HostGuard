# hostguard/checks/services.py
import os
import subprocess
from typing import Dict, Any


def has_systemctl() -> bool:
    """Check if systemctl exists (systemd systems)."""
    try:
        result = subprocess.run(
            ["which", "systemctl"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def has_ss() -> bool:
    """Check if ss exists."""
    try:
        result = subprocess.run(
            ["which", "ss"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def has_netstat() -> bool:
    """Check if netstat exists."""
    try:
        result = subprocess.run(
            ["which", "netstat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def check_systemctl_services() -> Dict[str, Any]:
    """Count systemd services and look for obvious odd ones."""
    if not has_systemctl():
        return {
            "check": "systemctl_services",
            "risk": "info",
            "explanation": "systemctl not available.",
            "score": 0.9,
        }

    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "-n", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        lines = result.stdout.strip().splitlines()
        # Assume first 2 lines are header, so:
        if len(lines) <= 2:
            count = 0
        else:
            count = len(lines) - 2

        if count == 0:
            return {
                "check": "systemctl_services",
                "risk": "warning",
                "explanation": "No running services found; unusual or minimal system.",
                "score": 0.5,
            }
        elif count <= 20:
            return {
                "check": "systemctl_services",
                "risk": "good",
                "explanation": f"{count} running services; normal desktop/server level.",
                "score": 0.8,
            }
        else:
            return {
                "check": "systemctl_services",
                "risk": "warning",
                "explanation": f"{count} running services; may be worth reviewing.",
                "score": 0.6,
            }

    except Exception as e:
        return {
            "check": "systemctl_services",
            "risk": "error",
            "explanation": f"Could not list services: {str(e)}",
            "score": 0.4,
        }


def check_listening_ports_ss() -> Dict[str, Any]:
    """Check listening TCP ports with ss."""
    if not has_ss():
        return {
            "check": "listening_ports_ss",
            "risk": "info",
            "explanation": "ss not available.",
            "score": 0.9,
        }

    try:
        result = subprocess.run(
            ["ss", "-tln"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        lines = result.stdout.strip().splitlines()
        ports = []

        for line in lines:
            fields = line.split()
            if len(fields) >= 5:
                local_addr = fields[4]
                if ":" in local_addr:
                    port = local_addr.split(":")[-1]
                else:
                    port = local_addr
                try:
                    port_num = int(port)
                    ports.append(port_num)
                except ValueError:
                    pass

        if len(ports) == 0:
            return {
                "check": "listening_ports_ss",
                "risk": "warning",
                "explanation": "No listening TCP ports found; unusual or minimal system.",
                "score": 0.5,
            }
        elif len(ports) <= 10:
            return {
                "check": "listening_ports_ss",
                "risk": "good",
                "explanation": f"{len(ports)} listening TCP ports; normal for a desktop system.",
                "score": 0.8,
            }
        else:
            return {
                "check": "listening_ports_ss",
                "risk": "warning",
                "explanation": f"{len(ports)} listening TCP ports; may be worth reviewing.",
                "score": 0.6,
            }

    except Exception as e:
        return {
            "check": "listening_ports_ss",
            "risk": "error",
            "explanation": f"Could not list ports with ss: {str(e)}",
            "score": 0.4,
        }


def check_listening_ports_netstat() -> Dict[str, Any]:
    """Check listening TCP ports with netstat."""
    if not has_netstat():
        return {
            "check": "listening_ports_netstat",
            "risk": "info",
            "explanation": "netstat not available.",
            "score": 0.9,
        }

    try:
        result = subprocess.run(
            ["netstat", "-tln"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        lines = result.stdout.strip().splitlines()
        ports = []

        for line in lines:
            if "LISTEN" not in line:
                continue
            fields = line.split()
            if len(fields) >= 4:
                addr = fields[3]
                if ":" in addr:
                    port = addr.split(":")[-1]
                else:
                    port = addr
                try:
                    port_num = int(port)
                    ports.append(port_num)
                except ValueError:
                    pass

        if len(ports) == 0:
            return {
                "check": "listening_ports_netstat",
                "risk": "warning",
                "explanation": "No listening TCP ports found.",
                "score": 0.5,
            }
        elif len(ports) <= 10:
            return {
                "check": "listening_ports_netstat",
                "risk": "good",
                "explanation": f"{len(ports)} listening TCP ports.",
                "score": 0.8,
            }
        else:
            return {
                "check": "listening_ports_netstat",
                "risk": "warning",
                "explanation": f"{len(ports)} listening TCP ports.",
                "score": 0.6,
            }

    except Exception as e:
        return {
            "check": "listening_ports_netstat",
            "risk": "error",
            "explanation": f"Could not list ports with netstat: {str(e)}",
            "score": 0.4,
        }


def run() -> Dict[str, Dict[str, Any]]:
    """Run all services/ports checks.

    This is 100% local, read‑only:
    - runs systemctl, ss, netstat,
    - only reads current state,
    - never modifies services or ports.

    Results help assess which services and ports are open and whether they are reasonable.
    """
    results = {}

    results["systemctl_services"] = check_systemctl_services()
    results["listening_ports_ss"] = check_listening_ports_ss()
    results["listening_ports_netstat"] = check_listening_ports_netstat()

    return results




