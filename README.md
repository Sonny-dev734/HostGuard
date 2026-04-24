# HostGuard – Linux Host Security Posture Auditor

HostGuard is a lightweight, local‑only Python tool that audits the security posture of a Linux host. It checks system configuration (SSH, firewall, users, services, and filesystem permissions), computes a numeric security score, and prints a structured text report. It is designed for Linux systems and is safe to run locally; no external network traffic is required.

## Ethical, clean, and local usage

HostGuard is:
- **100% local**: it runs only on the host where it is installed and does not connect to any external server or service.
- **Read‑only and non‑attacking**: it reads configuration files, system state, and running processes, but it does not modify system settings, send network traffic, or simulate attacks unless explicitly and safely extended later.
- **Ethical and educational**: it is designed to teach how Linux system security works and to improve your own machine's security posture, not to attack or scan other systems.

You should only run HostGuard on systems you own or have explicit permission to audit. It is not designed to be used against third‑party infrastructure.

## What it does

HostGuard performs the following operations:

- Runs security checks on the local machine, including:
  - SSH configuration (port, root login, authentication settings),
  - firewall rules (presence of basic deny/drop rules),
  - user accounts and sessions,
  - running services and open ports,
  - filesystem permissions and risky directories.
- Computes an overall security score between 0.0 (very risky) and 1.0 (excellent, minimal risk).
- Prints a structured text report that includes:
  - category (e.g., SSH, firewall, users, services, filesystem),
  - individual checks,
  - risk level (GOOD, WARNING, CRITICAL, ERROR),
  - human‑readable explanation,
  - and an overall summary with status.

This allows you to assess and improve your machine's security posture in a measurable, repeatable way.

## Directory structure

The project is designed with a clean, modular Python structure:

- `hostguard/` – main Python package:
  - `hostguard/config.py` – configuration and thresholds,
  - `hostguard/checks/` – directory for security checks (SSH, firewall, users, services, filesystem),
  - `hostguard/engine.py` – runs all checks and returns results,
  - `hostguard/reporter.py` – prints detailed reports.
- `main.py` – command‑line entry point.
- `README.md` – this documentation file.

## How to run it

1. Open a terminal and navigate to the project directory:

   ```bash
   cd ~/HostGuard
   ```

2. Run the script:

   ```bash
   python3 main.py
   ```

3. Observe the console output, which shows:
   - which checks passed,
   - which checks failed,
   - the risk level of each issue,
   - and the overall security score.

   Example statuses:
   - GOOD – security posture is strong,
   - WARNING – several issues need attention,
   - CRITICAL – many critical security issues present.

HostGuard is designed to be stable and robust; it avoids crashes by handling errors gracefully and running each check in isolation.

## Known limitations and possible issues

HostGuard is a **read‑only, local‑only** auditor, but like any software, it has **known limitations** and possible issues. A reader should understand the following:

### 1. Firewall check (`ufw_enabled`)

HostGuard checks `ufw` status with `sudo ufw status` and parses the first line to detect whether `ufw` is active. In some cases, this check may:

- Return `CRITICAL` if `ufw` is inactive or not installed,
- Return `ERROR` if the `ufw` command fails or is not available,
- Return `WARNING` if the output format is unexpectedly different and cannot be parsed cleanly.

This check is **robust but not perfect**; if you are sure `ufw` is active and HostGuard reports otherwise, you can verify manually with `sudo ufw status`. In future releases, the check may be improved to handle more output formats.

### 2. SSH configuration check

HostGuard checks SSH configuration by reading `/etc/ssh/sshd_config`. If this file is:

- Missing,
- Misconfigured,
- Or not present on your system,

HostGuard will report `ERROR` for SSH‑related checks, with explanations like “SSH config file not found; cannot audit SSH settings.” This is **not a bug** — it is a design‑level safeguard that ensures HostGuard does not crash when the file is absent.

### 3. User shells and accounts check

HostGuard reads `/etc/passwd` and counts user shells. It flags some shells (like `/usr/sbin/nologin`) as “suspicious” based on a predefined list. In practice, many Linux systems have **dozens of system accounts** (for services and daemons), so HostGuard may report a high number of “suspicious‑shell” accounts even though they are **completely normal** and not dangerous.

This is **not a false positive** in terms of security — it is a **design choice** that treats non‑standard shells as “suspicious.” If you wish, you can customize the list of “bad” shells in `checks/users.py` to fit your system.

### 4. Services and ports checks

HostGuard uses `systemctl`, `ss`, and `netstat` to detect running services and listening ports. In some cases:

- `systemctl` may not be available (on non‑systemd systems),
- `ss` or `netstat` may return unexpected or incomplete output,
- ports may be reported differently by `ss` vs `netstat`.

HostGuard handles these gracefully, returning `INFO` or `ERROR` where appropriate, but readers should be aware that **port‑listing tools may differ in output**.

### 5. Filesystem permissions

HostGuard walks `/etc`, `/tmp`, `/var`, `/home`, and `/root` to detect overly permissive (world‑writable) files. This check is **safe and read‑only**, but it may be slow on very large filesystems. If you encounter performance issues, you can limit the directories checked or adjust the thresholds in `checks/filesystem.py`.

## Privacy and security

HostGuard is designed to be **privacy‑preserving** and **safe**:

- It **does not collect** or transmit any personal data, logs, or configuration content.
- It **does not send** any data to external servers, analytics, or telemetry systems.
- It **only reads** local configuration and system state, and it **never modifies** them unless you explicitly extend it later.

All data generated by HostGuard (e.g., reports, logs) remains **local to your machine** and is not published or shared by default.

## Future extensions (optional)

HostGuard can be extended safely to include:
- additional checks (kernel hardening, logging, anti‑malware tools, etc.),
- optional export formats (e.g., JSON, CSV),
- optional color‑coded output (using the `rich` library or similar).

Any extensions that involve network traffic or interaction with external systems must be added explicitly and separately, and must respect ethical usage rules.

---

HostGuard is provided for educational and self‑improvement purposes only. The project does not guarantee perfect security and is not a replacement for enterprise‑grade security tools.





