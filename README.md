# Guardian Network Scanner

```
#############################################
#        Guardian Network Scanner         #
#          Network Security Focus         #
#############################################
```

**Guardian is a network security scanner designed to provide in-depth security posture analysis. It examines network configurations, listening services, active local network traffic (including protocol and approximate volume insights on Linux), and remote targets. The scanner also includes capabilities to detect potential ARP and DNS spoofing, analyze SSL/TLS certificates, identify promiscuous mode interfaces, and perform detailed traceroute analysis (with RTT and packet loss statistics).**

It gathers network interface information, analyzes SSH configurations, examines authentication logs, summarizes active local connections with protocol and traffic volume details (Linux-specific for volume), traces routes to external targets with per-hop RTT/loss analysis, profiles remote hosts by scanning common ports (including SSL/TLS certificate analysis for HTTPS services), analyzes the local ARP cache for anomalies, compares DNS resolutions to detect potential spoofing, checks for local promiscuous mode interfaces, and (experimentally) probes remote targets for promiscuous mode. This helps identify potential vulnerabilities or misconfigurations related to network security and potential sniffing activities.

## Features

Guardian performs a range of network-focused checks, organized into modules:

*   **Network Scanning (`network_scan.py`)**:
    *   Identifies network interfaces and associated IP addresses (IPv4/IPv6).
    *   Discovers all listening TCP and UDP ports.
    *   Analyzes listening ports for risky services (e.g., Telnet, FTP), unencrypted protocols (HTTP), and services exposed on all interfaces.
    *   Correlates listening ports with process IDs, names, and users (requires appropriate permissions).
    *   **Traceroute**: Identifies hops to a target, including IP, hostname, and now provides detailed Round-Trip Time (RTT) statistics (min/avg/max) and packet loss percentage per hop. Generates findings for high latency or loss.
*   **Local Traffic Analysis (`local_traffic_analyzer.py`)**:
    *   Summarizes active network connections on the host (TCP and UDP).
    *   Identifies processes associated with these active connections.
    *   Focuses on established ingress/egress connections, providing insights into current network communication entry/exit points.
    *   Attempts basic application-layer protocol identification (e.g., HTTP, TLS/SSL, SSH) for active TCP connections on common ports.
    *   On Linux systems, provides experimental traffic volume analysis (approximate bytes sent/received) for established TCP connections by parsing `ss` command output.
*   **SSH Configuration Analysis (`ssh_analysis.py`)**:
    *   Analyzes `/etc/ssh/sshd_config` for insecure settings such as Protocol 1, root login, password authentication, empty passwords, and X11 forwarding.
    *   Checks settings like `MaxAuthTries`, `LoginGraceTime`, and client keep-alives.
*   **Log Analysis (`log_analysis.py`)**:
    *   Analyzes `/var/log/auth.log` (or equivalent system authentication log) for failed login attempts, successful SSH logins, and `sudo` command usage, providing insights into potential unauthorized access attempts or misuse.
*   **Target Host Profiling (`target_profiler.py`)**:
    *   Performs a basic TCP port scan on a specified remote target host for common service ports (e.g., 21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080).
    *   Attempts to grab service banners from open ports to identify running services.
    *   **SSL/TLS Certificate Analysis**: When port 443 is found open on a target specified with `--target-host`, this feature retrieves and analyzes its SSL/TLS certificate. Checks include hostname verification (CN/SAN vs target domain), validity period, self-signed certificate heuristics, basic issuer details, and the presence of the HSTS header.
*   **MiTM Detection (`mitm_detector.py`)**:
    *   **ARP Cache Analysis**: Detects potential ARP spoofing by checking for multiple MAC addresses associated with the default gateway IP in the local ARP cache.
    *   **DNS Spoofing Detection**: Compares DNS resolutions for a set of common domains between the system's configured DNS resolver and known public DNS servers. Discrepancies are flagged as potential DNS spoofing. Requires the `dnspython` library to be installed.
    *   **Local Promiscuous Mode Detection**: Checks local network interfaces for promiscuous mode using OS-specific commands. Highlights interfaces that are capturing all traffic on their network segment.
    *   **Remote Promiscuous Mode Detection (Experimental)**: Attempts to detect if a remote target (specified by `--target-host`) might be in promiscuous mode by sending a specially crafted ICMP echo request (ping with a bogus destination MAC address). This test is indicative, not definitive, and requires the `scapy` library to be installed.
*   **Concurrency**: Utilizes Python's `multiprocessing` to run checks concurrently for improved performance.

## Requirements

*   **Python**: Python 3.6+
*   **Libraries**:
    *   `psutil` (for core network and process information)
    *   `dnspython` (optional, for DNS Spoofing Detection feature)
    *   `scapy` (optional, for experimental Remote Promiscuous Mode Detection feature)
    ```bash
    pip install psutil dnspython scapy
    ```
    Alternatively, install individually:
    ```bash
    pip install psutil  # Core dependency
    # For DNS Spoofing Detection:
    pip install dnspython
    # For Remote Promiscuous Mode Detection (Experimental):
    pip install scapy
    ```
*   **Permissions**: **Root privileges** are highly recommended for a complete scan. Some checks, like accessing all process details for network connections, reading specific log files, reliable ARP table access, and raw socket operations for Scapy, require root access. The script will run without root but may produce incomplete results and warnings for certain checks.
*   **External Commands**: None required for the current set of network-focused modules. (Note: Scapy itself might have underlying dependencies like Npcap on Windows for raw packet capabilities).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd guardian-scanner # Or your directory name
    ```
2.  **Install requirements:**
    If a `requirements.txt` file is present and lists `psutil`, `dnspython`, and `scapy`:
    ```bash
    pip install -r requirements.txt
    ```
    Otherwise, install manually as shown in the Libraries subsection above.

## Usage

Run the script with Python 3. Root privileges are recommended:

```bash
sudo python3 guardian.py
```

To utilize the traceroute and target profiling features, specify a target host:
```bash
sudo python3 guardian.py --target-host <hostname_or_IP>
```
The `--target-host` argument is required for the traceroute, remote target profiling (including SSL/TLS analysis), and experimental remote promiscuous mode detection modules to run.
Other local scan modules, including ARP cache analysis, DNS spoofing detection, and local promiscuous mode detection, will run regardless of this argument.
Most detection modules (ARP, DNS, promiscuous mode) benefit from root/administrator privileges for reliable system information access and raw socket operations (for Scapy).
The DNS Spoofing Detection module runs by default but will skip its checks and issue a warning if the `dnspython` library is not installed. Similarly, the Remote Promiscuous Mode Detection will be skipped if `scapy` is not available or if the target is not specified.

**Output:**

1.  **Banner**: Displays the Guardian Scanner banner.
2.  **Module Progress**: Indicates when each analysis module starts and finishes (useful for tracking long-running scans like file system checks).
3.  **Warnings/Errors**: Any errors encountered during the scan (e.g., permission denied, file not found) will be printed, often in red or yellow.
4.  **Scan Summary**:
    *   **Findings by Severity**: A count of findings categorized as CRITICAL, HIGH, MEDIUM, LOW, INFO.
    *   **Key Statistics Gathered**: A summary of key metrics collected by the modules. This includes network interface details, listening port counts, SSH configuration notes, log analysis summaries (failed logins, sudo commands), active connection counts (with protocol identification and, on Linux, traffic volume estimates), detailed traceroute results (including RTT and packet loss per hop), remote target profiles (open ports, banners, SSL/TLS certificate details), and MiTM detection results (ARP, DNS, promiscuous mode).
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

*   `utils.py`: Shared constants (colors, severities), and helper functions like `run_command`.
*   `network_scan.py`: Interface, IP, listening port scanning, and traceroute functionality with detailed RTT and packet loss analysis for traceroute.
*   `local_traffic_analyzer.py`: Analysis of active local network connections, including protocol identification and (Linux-specific) traffic volume estimation.
*   `ssh_analysis.py`: SSH daemon configuration checks.
*   `log_analysis.py`: Authentication log checks.
*   `target_profiler.py`: Remote target port scanning, banner grabbing, and SSL/TLS certificate analysis.
*   `mitm_detector.py`: ARP cache analysis, DNS spoofing detection, local promiscuous mode detection, and experimental remote promiscuous mode detection.

## OPSEC Considerations

*   **Privileges**: Running as root provides the most comprehensive scan (e.g., for correlating network services to PIDs and users, accessing restricted log files, using raw sockets for Scapy) but also carries inherent risks.
*   **Network Impact (Passive vs. Active)**:
    *   Most local scanning components are passive (checking local listening ports, interfaces, configurations, logs, ARP cache).
    *   **Active Measures**: The **traceroute**, **target profiling** (port scanning, banner grabbing, SSL/TLS analysis), and **experimental remote promiscuous mode detection** features are *active* measures.
        *   Traceroute sends packets to discover routes and is generally considered low risk, but it does interact with intermediate network devices.
        *   Port scanning and SSL/TLS certificate retrieval involve direct interaction with the target and **can be easily detected by the target system's firewalls, Intrusion Detection/Prevention Systems (IDS/IPS), and logging mechanisms.**
        *   The experimental remote promiscuous mode test sends a specifically crafted ICMP packet to the target, which could also be logged or detected.
        *   **Users must ensure they have explicit permission to scan any remote targets.** Unauthorized scanning can be unethical or illegal.
*   **System Load**: While less intensive than full system scans, network and log analysis can still consume resources. The use of multiprocessing helps, but be aware of potential load.
*   **Log Noise**: Some checks, especially informational ones from log analysis or active connection listings, can generate significant output. The findings are prioritized by severity.
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