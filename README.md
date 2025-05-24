# Guardian Network Scanner

```
#############################################
#        Guardian Network Scanner         #
#          Network Security Focus         #
#############################################
```

**Guardian is a network security scanner designed to provide in-depth security posture analysis of network configurations and listening services.**

It gathers network interface information, analyzes SSH configurations, examines authentication logs, and identifies potential vulnerabilities or misconfigurations related to network security.

## Features

Guardian performs a range of network-focused checks, organized into modules:

*   **Network Scanning (`network_scan.py`)**:
    *   Identifies network interfaces and associated IP addresses (IPv4/IPv6).
    *   Discovers all listening TCP and UDP ports.
    *   Analyzes listening ports for risky services (e.g., Telnet, FTP), unencrypted protocols (HTTP), and services exposed on all interfaces.
    *   Correlates listening ports with process IDs, names, and users (requires appropriate permissions).
*   **SSH Configuration Analysis (`ssh_analysis.py`)**:
    *   Analyzes `/etc/ssh/sshd_config` for insecure settings such as Protocol 1, root login, password authentication, empty passwords, and X11 forwarding.
    *   Checks settings like `MaxAuthTries`, `LoginGraceTime`, and client keep-alives.
*   **Log Analysis (`log_analysis.py`)**:
    *   Analyzes `/var/log/auth.log` (or equivalent system authentication log) for failed login attempts, successful SSH logins, and `sudo` command usage, providing insights into potential unauthorized access attempts or misuse.
*   **Concurrency**: Utilizes Python's `multiprocessing` to run checks concurrently for improved performance.

## Requirements

*   **Python**: Python 3.6+
*   **Libraries**: `psutil`
    ```bash
    pip install psutil
    ```
*   **Permissions**: **Root privileges** are highly recommended for a complete scan. Some checks, like accessing all process details for network connections or reading specific log files (e.g. `/etc/shadow` if `log_analysis` were to expand to it, or `/etc/sudoers` for `user_analysis` if it were present), require root access. The script will run without root but may produce incomplete results and warnings for certain checks.
*   **External Commands**: None required for the current set of network-focused modules.

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
    print(f"\n[+] Full report saved to {report_file}")
except Exception as e:
    print(f"\n{COLOR_RED}Error saving report: {e}{COLOR_RESET}")
```

## Modules Overview

The core logic is broken down into modules within the `modules/` directory:

*   `utils.py`: Shared constants (colors, severities).
*   `network_scan.py`: Interface, IP, and listening port scanning.
*   `ssh_analysis.py`: SSH daemon configuration checks.
*   `log_analysis.py`: Authentication log checks.

## OPSEC Considerations

*   **Privileges**: Running as root provides the most comprehensive scan (e.g., for correlating network services to PIDs and users, or accessing restricted log files) but also carries inherent risks.
*   **Network Impact**: The current network scanning components are passive (checking local listening ports and interfaces). Be mindful of network policies if active scanning capabilities are added in the future.
*   **System Load**: While less intensive than full system scans, network and log analysis can still consume resources. The use of multiprocessing helps, but be aware of potential load.
*   **Log Noise**: Some checks, especially informational ones from log analysis, can generate significant output. The findings are prioritized by severity.
*   **False Positives/Negatives**: While efforts are made to be accurate, security scanning can sometimes produce false positives or miss things. Results should always be reviewed and correlated with other information.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests for:

*   Bug fixes
*   Adding new checks and modules
*   Improving existing detection logic (e.g., more robust regex, better platform compatibility)
*   Enhancing reporting and output formatting
*   Adding support for different operating systems or log formats

## License

This project is licensed under the MIT License.