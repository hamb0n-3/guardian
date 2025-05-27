# Guardian Scanner

```
#############################################
#            Guardian Scanner             #
#        Advanced Defense & OPSEC         #
#############################################
```

**Guardian is an advanced host and network defense scanner designed to provide in-depth security posture analysis with a focus on operational security (OPSEC) heuristics.**

It gathers extensive system and network information, analyzes configurations, checks running processes, examines logs, and identifies potential vulnerabilities or misconfigurations based on security best practices and common attack vectors.

## Features

Guardian performs a wide range of checks, organized into modules:

*   **System Information (`system_info.py`)**: Gathers OS details, kernel version, hostname, architecture, and resource utilization (CPU, Memory).
*   **Network Scanning (`network_scan.py`)**:
    *   Identifies network interfaces and associated IP addresses (IPv4/IPv6).
    *   Discovers all listening TCP and UDP ports.
    *   Analyzes listening ports for risky services (e.g., Telnet, FTP), unencrypted protocols (HTTP), and services exposed on all interfaces.
    *   Correlates listening ports with process IDs, names, and users.
    *   **DHCP Discovery / Rogue DHCP Detection**:
        *   Attempts to discover active DHCP servers on the network segments of its interfaces using Nmap's `broadcast-dhcp-discover` NSE script.
        *   Compares discovered DHCP server IPs against a configurable list of authorized servers (`AUTHORIZED_DHCP_SERVERS` in `guardian.py`).
        *   Generates findings for "Authorized DHCP Server Found", "Rogue DHCP Server Detected" (if not in the authorized list), or "Unconfirmed DHCP Server" (if the authorized list is empty).
        *   Also reports errors like Nmap not being found or the scan failing.
        *   **Requires Nmap to be installed and Guardian to be run with `sudo` (or as root)** due to Nmap's need for privileged network access for this script.
*   **Process Analysis (`process_analysis.py`)**:
    *   Lists all running processes with details (PID, PPID, user, command line, CWD).
    *   Identifies processes running as root (excluding common system processes).
    *   Detects processes running from suspicious locations (e.g., `/tmp`, `/var/tmp`).
    *   Flags potentially malicious command patterns (e.g., `nc` listeners, simple HTTP servers).
*   **SSH Configuration Analysis (`ssh_analysis.py`)**:
    *   Analyzes `/etc/ssh/sshd_config` for insecure settings (Protocol 1, root login, password authentication, empty passwords, X11 forwarding, weak crypto - *crypto checks planned*).
    *   Checks settings like `MaxAuthTries`, `LoginGraceTime`, and client keep-alives.
*   **User Account Analysis (`user_analysis.py`)**:
    *   Analyzes `/etc/passwd` for non-root accounts with UID 0, non-standard shells, guessable usernames, and missing home directories.
    *   Analyzes `/etc/shadow` (requires root) for accounts with empty password hashes and non-expiring passwords.
    *   Performs basic checks on `/etc/sudoers` (requires root) for `NOPASSWD` entries and overly broad permissions.
*   **File System Analysis (`file_system.py`)**:
    *   Searches common system paths (`/etc`, `/var`, `/home`, etc.) for potentially sensitive file types (`.key`, `.pem`, `.sql`, config files, scripts, password files).
    *   Identifies world-writable files.
    *   Identifies world-writable directories *without* the sticky bit set.
    *   Finds non-standard SUID/SGID files (excluding a common whitelist).
    *   Detects files/directories with dangling ownership (UID/GID not present in `/etc/passwd` or `/etc/group`).
*   **Kernel Parameter Analysis (`kernel_params.py`)**:
    *   Checks critical `sysctl` parameters against security recommendations (e.g., ASLR, SYN cookies, IP forwarding, ICMP handling, RP filter, ptrace scope, user namespaces).
*   **Log Analysis (`log_analysis.py`)**:
    *   Analyzes `/var/log/auth.log` (or equivalent) for failed login attempts, successful SSH logins, and `sudo` command usage. (*More log sources and patterns planned*).
*   **Systemd Analysis (`services_timers.py`)**:
    *   Lists running systemd services and checks for units running from suspicious paths or known risky services.
    *   Lists active systemd timers and flags potentially suspicious frequent execution intervals.
*   **Environment Detection (`environment_detection.py`)**:
    *   Attempts to detect if running inside a container (Docker, LXC, Kubernetes) or a virtual machine (KVM, VMware, VirtualBox, QEMU, Hyper-V) using various methods (`systemd-detect-virt`, cgroups, DMI, specific files).
*   **Concurrency**: Utilizes Python's `multiprocessing` to run checks concurrently for improved performance.

## Requirements

*   **Python**: Python 3.6+
*   **Libraries**: `psutil`
    ```bash
    pip install psutil
    ```
*   **Permissions**: **Root privileges** are highly recommended for a complete scan. Many checks (reading shadow file, analyzing sudoers, accessing all process details, checking certain sysctl parameters, using `dmidecode`) require root access. The script will run without root but will produce incomplete results and warnings.
*   **External Commands (Optional but Recommended)**:
    *   `systemd-detect-virt` (for reliable VM/container detection)
    *   `dmidecode` (for VM detection via DMI - requires root)
    *   `systemctl` (for service/timer analysis)
    *   `sysctl` (for kernel parameter analysis)
    *   `nmap` (for DHCP Discovery and potentially other future network probes)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd guardian-scanner # Or your directory name
    ```
2.  **Install requirements:**
    ```bash
    pip install -r requirements.txt
    ```
    (Or manually: `pip install psutil`)

## Usage

Run the script with Python 3. Root privileges are recommended:

```bash
sudo python3 guardian.py
```

**Output:**

1.  **Banner**: Displays the Guardian Scanner banner.
2.  **Module Progress**: Indicates when each analysis module starts and finishes (useful for tracking long-running scans like file system checks).
3.  **Warnings/Errors**: Any errors encountered during the scan (e.g., permission denied, file not found) will be printed, often in red or yellow.
4.  **Scan Summary**:
    *   **Findings by Severity**: A count of findings categorized as CRITICAL, HIGH, MEDIUM, LOW, INFO.
    *   **Key Statistics Gathered**: A summary of key metrics collected by the modules (OS info, resource usage, network counts, environment type, etc.).
5.  **Detailed Findings**: A list of all findings, sorted by severity (Critical first), including:
    *   Severity Level
    *   Title
    *   Description of the issue
    *   Recommendation for mitigation (if available)

**JSON Report (Optional):**

The script includes commented-out code at the end of `guardian.py` to save a detailed JSON report containing all findings and statistics. Uncomment this section if you want to save the report:

```python
# Optional: Save full report
try:
    report_file = f"guardian_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    # Convert manager proxies to standard types for JSON
    report_data = {
        # Deep copy managed dict to standard dict
        "statistics": json.loads(json.dumps(managed_stats._getvalue())),
        "findings": {k: list(v) for k, v in managed_findings.items()}
    }
    # Ensure stats dict is serializable (complex objects might fail)
    # Basic conversion for now:
    def default_serializer(obj):
        # Add handlers for other non-serializable types if needed
        return str(obj) # Fallback

    with open(report_file, "w") as f:
        json.dump(report_data, f, indent=4, default=default_serializer)
    print(f"
[+] Full report saved to {report_file}")
except Exception as e:
    print(f"
{COLOR_RED}Error saving report: {e}{COLOR_RESET}")
```

## Modules Overview

The core logic is broken down into modules within the `modules/` directory:

*   `utils.py`: Shared constants (colors, severities) and helper functions (`run_command`).
*   `system_info.py`: Basic OS and hardware info.
*   `network_scan.py`: Interface, IP, listening port scanning, traceroute, and DHCP discovery.
*   `process_analysis.py`: Running process enumeration and analysis, including protocol identification and I/O volume.
*   `ssh_analysis.py`: SSH daemon configuration checks.
*   `user_analysis.py`: User account, password policy, and sudoers analysis.
*   `file_system.py`: Sensitive file and insecure permission scanning.
*   `kernel_params.py`: `sysctl` security parameter checks.
*   `log_analysis.py`: Authentication log checks.
*   `services_timers.py`: Systemd service and timer checks.
*   `environment_detection.py`: Container/VM detection.

## OPSEC Considerations

*   **Privileges**: Running as root provides the most comprehensive scan but also carries inherent risks. Understand why root is needed for specific checks.
*   **Network Impact**: The network scanning components are passive (checking local listening ports and interfaces), but future additions might include active scanning. Be mindful of network policies.
*   **System Load**: File system scanning and process iteration can be resource-intensive, especially on systems with many files or processes. The use of multiprocessing helps, but be aware of potential load during the scan.
*   **Log Noise**: Some checks, especially informational ones, can generate significant output. The findings are prioritized by severity.
*   **False Positives/Negatives**: While efforts are made to be accurate, security scanning can sometimes produce false positives (flagging something benign) or miss things (false negatives). Results should always be reviewed and correlated with other information.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests for:

*   Bug fixes
*   Adding new checks and modules
*   Improving existing detection logic (e.g., more robust regex, better platform compatibility)
*   Enhancing reporting and output formatting
*   Adding support for different operating systems or init systems

## License

*(Specify License Here - e.g., MIT License, Apache 2.0, or state if unlicensed)*
Currently unlicensed. 