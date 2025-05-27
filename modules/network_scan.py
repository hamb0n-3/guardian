#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Network Scanning (Interfaces, Listening Ports, Traceroute, DHCP Discovery)
"""

import socket
import psutil
import subprocess
import re
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH
)

def get_network_interfaces(managed_stats, managed_findings, add_finding_func):
    """Gathers network interface info, storing results in managed dicts."""
    print(f"{COLOR_GREEN}[*] Gathering Network Interface Information...{COLOR_RESET}")
    if 'network' not in managed_stats:
        managed_stats['network'] = {} 

    interfaces_local = {}
    try:
        all_interfaces = psutil.net_if_addrs()
        if not all_interfaces:
             add_finding_func(managed_findings, SEVERITY_MEDIUM, "No Network Interfaces Found", "psutil could not detect any network interfaces.")
             managed_stats['network']['interfaces_error'] = "No interfaces detected by psutil"
             return

        for name, snicaddrs in all_interfaces.items():
            interface_info = {'addresses': []} 
            for snicaddr in snicaddrs:
                addr_info = {
                    'family': str(snicaddr.family),
                    'address': snicaddr.address,
                    'netmask': snicaddr.netmask,
                    'broadcast': snicaddr.broadcast
                }
                interface_info['addresses'].append(addr_info)

                family_str = "IPv4" if snicaddr.family == socket.AF_INET else "IPv6" if snicaddr.family == socket.AF_INET6 else "Other"
                add_finding_func(
                    managed_findings,
                    SEVERITY_INFO,
                    f"Network Interface: {name} ({family_str})",
                    f"Address: {snicaddr.address}, Netmask: {snicaddr.netmask}, Broadcast: {snicaddr.broadcast}"
                )
            interfaces_local[name] = interface_info
        
        current_network_stats = managed_stats['network']
        current_network_stats['interfaces'] = interfaces_local
        managed_stats['network'] = current_network_stats

    except Exception as e:
        print(f"{COLOR_RED}Error gathering network interface info: {e}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Network Interface Error", f"Failed to gather network interface info: {e}")
        current_network_stats = managed_stats.get('network', {})
        current_network_stats['interfaces_error'] = str(e)
        managed_stats['network'] = current_network_stats

def get_listening_ports(managed_stats, managed_findings, add_finding_func):
    """Gathers listening port info, storing results in managed dicts."""
    print(f"{COLOR_GREEN}[*] Gathering Listening Ports...{COLOR_RESET}")
    if 'network' not in managed_stats:
        managed_stats['network'] = {}

    listening_ports_local = []
    listening_count = 0

    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                listening_count += 1
                port_info = {
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_addr": conn.laddr.ip,
                    "local_port": conn.laddr.port,
                    "pid": conn.pid,
                    "process_name": "N/A",
                    "username": "N/A"
                }
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        port_info["process_name"] = proc.name()
                        port_info["username"] = proc.username()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        port_info["process_name"] = "(Access Denied or No Such Process)"
                    except Exception as proc_e:
                         port_info["process_name"] = f"(Error: {proc_e})"
                
                listening_ports_local.append(port_info)

                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                family_str = "IPv4" if conn.family == socket.AF_INET else "IPv6"
                add_finding_func(
                    managed_findings, SEVERITY_INFO,
                    f"Listening Port: {proto}/{port_info['local_port']} ({family_str})",
                    f"Address: {port_info['local_addr']}, PID: {port_info['pid'] or 'N/A'}, Process: {port_info['process_name']}, User: {port_info['username']}"
                )
                if port_info['local_addr'] == "0.0.0.0" or port_info['local_addr'] == "::":
                    add_finding_func(
                        managed_findings, SEVERITY_MEDIUM,
                        f"Port {proto}/{port_info['local_port']} Listening on All Interfaces",
                        f"Process '{port_info['process_name']}' (PID: {port_info['pid'] or 'N/A'}, User: {port_info['username']}) listening on {port_info['local_addr']}, potentially accessible externally.",
                        "Verify need for external exposure. If not needed, bind to specific internal IPs."
                    )
                if port_info['local_port'] == 21: # FTP
                     add_finding_func(managed_findings, SEVERITY_HIGH, "FTP Server Detected", f"Port 21 (FTP) open (Process: {port_info['process_name']}). FTP is insecure.", "Use SFTP/FTPS instead. Disable FTP if not essential.")
                if port_info['local_port'] == 23: # Telnet
                     add_finding_func(managed_findings, SEVERITY_HIGH, "Telnet Server Detected", f"Port 23 (Telnet) open (Process: {port_info['process_name']}). Telnet is insecure.", "Use SSH instead. Disable Telnet if not essential.")
                if port_info['local_port'] == 80 and port_info['local_addr'] != "127.0.0.1" and port_info['local_addr'] != "::1": # HTTP
                     add_finding_func(managed_findings, SEVERITY_MEDIUM, "Unencrypted HTTP Service Detected", f"Port 80 (HTTP) open on non-localhost ({port_info['local_addr']}) (Process: {port_info['process_name']}).", "Use HTTPS (port 443) for encrypted web traffic.")

    except psutil.AccessDenied:
         warning_msg = "Access denied retrieving network connection details. Run as root for full info."
         print(f"{COLOR_YELLOW}Warning: {warning_msg}{COLOR_RESET}")
         add_finding_func(managed_findings, SEVERITY_LOW, "Network Scan Permissions Issue", warning_msg)
    except Exception as e:
        error_msg = f"Failed to gather listening port info: {e}"
        print(f"{COLOR_RED}Error gathering listening ports: {e}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Listening Port Error", error_msg)
        current_network_stats = managed_stats.get('network', {})
        current_network_stats['listening_ports_error'] = str(e)
        managed_stats['network'] = current_network_stats

    current_network_stats = managed_stats.get('network', {})
    current_network_stats['listening_ports'] = listening_ports_local
    current_network_stats['listening_ports_count'] = listening_count
    managed_stats['network'] = current_network_stats

def perform_traceroute(managed_stats, managed_findings, add_finding_func, target_host):
    """
    Performs a traceroute to the target host, analyzes RTT and packet loss,
    and stores results in managed_stats and managed_findings.

    Args:
        managed_stats (Manager.dict): Shared dictionary for statistics.
        managed_findings (Manager.list): Shared list for findings.
        add_finding_func (function): Function to add a finding.
        target_host (str): The hostname or IP address to trace.
    """
    print(f"{COLOR_GREEN}[*] Performing traceroute to {target_host}...{COLOR_RESET}")

    if 'network' not in managed_stats:
        managed_stats['network'] = {}
    if 'traceroute' not in managed_stats['network']:
        managed_stats['network']['traceroute'] = {}

    # Initialize storage for this specific target
    managed_stats['network']['traceroute'][target_host] = {"hops": [], "error": None, "summary": ""}
    hop_details_list = []
    
    # Command: traceroute -n (numeric, no DNS) -q 1 (1 query per hop) -w 1 (1 sec wait time per query)
    # -m 30 (max 30 hops). Standard traceroute uses UDP by default.
    # Using -I for ICMP ECHO probes can be more reliable if permissions allow (often needs root).
    # Defaulting to UDP to avoid mandatory root, but ICMP could be a configurable option later.
    command = ["traceroute", "-n", "-q", "1", "-w", "1", "-m", "30", target_host]

    try:
        # Using universal_newlines=True for text mode, simplifying stdout/stderr handling.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True)
        # Increased timeout to 60 seconds for potentially long traceroutes.
        stdout, stderr = process.communicate(timeout=60)

        if stderr and "command not found" in stderr.lower() or "no such file or directory" in stderr.lower():
            error_msg = f"Traceroute command not found. Please install it (e.g., 'sudo apt-get install traceroute' or 'sudo yum install traceroute')."
            print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
            add_finding_func(managed_findings, SEVERITY_HIGH, "Traceroute Execution Error", error_msg, f"Host: {target_host}, Command: {' '.join(command)}")
            managed_stats['network']['traceroute'][target_host]['error'] = error_msg
            return
        
        # Some traceroute versions output "Cannot handle `host' problem: Host not found" to stderr for invalid hosts
        if stderr and ("Host not found" in stderr or "Name or service not known" in stderr):
            error_msg = f"Traceroute failed for {target_host}: Host not found or DNS resolution failure. Error: {stderr.strip()}"
            print(f"{COLOR_RED}{error_msg}{COLOR_RESET}")
            add_finding_func(managed_findings, SEVERITY_HIGH, "Traceroute Host Resolution Error", error_msg, f"Host: {target_host}, Command: {' '.join(command)}")
            managed_stats['network']['traceroute'][target_host]['error'] = stderr.strip()
            return

        # Other errors during execution (e.g. network unreachable if not caught by specific checks)
        if process.returncode != 0 and stderr:
            error_msg = f"Traceroute command failed for {target_host}. Exit code: {process.returncode}. Error: {stderr.strip()}"
            print(f"{COLOR_RED}{error_msg}{COLOR_RESET}")
            add_finding_func(managed_findings, SEVERITY_HIGH, "Traceroute Execution Error", error_msg, f"Host: {target_host}, Command: {' '.join(command)}")
            managed_stats['network']['traceroute'][target_host]['error'] = stderr.strip()
            return

        if not stdout:
            # This can happen if the target is the first hop (e.g. localhost) or if traceroute gives no output for another reason
            warning_msg = f"Traceroute to {target_host} produced no standard output. stderr: {stderr.strip() if stderr else 'None'}"
            print(f"{COLOR_YELLOW}Warning: {warning_msg}{COLOR_RESET}")
            add_finding_func(managed_findings, SEVERITY_LOW, "Traceroute Empty Output", warning_msg, f"Host: {target_host}, Command: {' '.join(command)}")
            managed_stats['network']['traceroute'][target_host]['summary'] = "No standard output from traceroute."
            # managed_stats['network']['traceroute'][target_host]['error'] could be set if stderr also indicated an issue
            if stderr:
                 managed_stats['network']['traceroute'][target_host]['error'] = stderr.strip()
            return
        
        # Regex to parse traceroute output lines. Handles various formats.
        # Catches: hop_num, ip_address (or hostname), rtt
        # Example: " 1  192.168.1.1  0.543 ms"
        # Example: " 2  some.host.name (10.0.0.1)  1.234 ms"
        # Example: " 3  * * *" (timeout)
        # Example: " 4  10.0.0.2 (10.0.0.2)  1.234 ms" (IP shown twice if -n not fully effective or it's an IP)
        # Example: " 5  host.example.com (1.2.3.4)  1.234 ms  1.345 ms  1.456 ms" (multiple RTTs if -q > 1)
        # Since we use -q 1, we expect only one RTT.
        hop_pattern = re.compile(
            r"^\s*(\d+)\s+"                                # 1: Hop number
            r"([\w\.\-]+|\*)"                             # 2: IP address or hostname or '*'
            r"(?:\s+\(([\d\.]+)\))?"                       # 3: Optional actual IP if hostname was resolved (e.g. by traceroute itself despite -n)
            r"(?:\s+([\d\.]+)\s*ms)?"                      # 4: RTT for the first probe
            # r"(?:\s+([\d\.]+)\s*ms)?"                    # 5: RTT for the second probe (if -q > 1)
            # r"(?:\s+([\d\.]+)\s*ms)?"                    # 6: RTT for the third probe (if -q > 1)
        )

        lines = stdout.strip().split('\n')
        # First line is often a header, e.g., "traceroute to google.com (172.217.160.142), 30 hops max, 60 byte packets"
        # We are interested in lines starting with hop numbers.
        
        target_ip_resolved_early = None
        try:
            # Resolve target_host to IP upfront for accurate "target reached" check
            # socket.getaddrinfo can return multiple results, use the first one's IP
            addrinfo = socket.getaddrinfo(target_host, None)
            target_ip_resolved_early = addrinfo[0][4][0] # [0] for first result, [4] for sockaddr, [0] for IP
        except socket.gaierror:
            # This case should ideally be caught by traceroute itself, but as a fallback:
            error_msg = f"Could not resolve target_host '{target_host}' to an IP address before parsing hops."
            print(f"{COLOR_YELLOW}Warning: {error_msg}{COLOR_RESET}")
            add_finding_func(managed_findings, SEVERITY_LOW, "Traceroute Pre-computation Warning", error_msg, f"Host: {target_host}")
            # Continue, traceroute might still work with an IP or handle the error.
            # If traceroute also fails, its error will be caught.

        target_reached_flag = False
        for line in lines:
            line = line.strip()
            if not line or not line[0].isdigit(): # Skip headers/empty lines
                continue

            match = hop_pattern.match(line)
            if match:
                hop_num = int(match.group(1))
                name_or_ip_field = match.group(2) # This is what traceroute shows: IP if -n, or name
                resolved_ip_in_parentheses = match.group(3) # IP in () if name was shown
                rtt_str = match.group(4)
                
                current_hop_ip = name_or_ip_field # Default to this
                if resolved_ip_in_parentheses:
                    current_hop_ip = resolved_ip_in_parentheses # Prefer the IP from parentheses if available
                
                rtt_ms = None
                packet_loss_percent = 0.0 # Default assumption for -q 1 if RTT is present

                if name_or_ip_field == "*":
                    current_hop_ip = "N/A (Timeout)"
                    packet_loss_percent = 100.0 # All probes for this hop timed out (given -q 1)
                elif rtt_str:
                    try:
                        rtt_ms = float(rtt_str)
                    except ValueError:
                        rtt_ms = None # Should not happen with regex but good practice
                else:
                    # Hop was listed but no RTT value (e.g. "5  some.router.net")
                    # This can indicate the probe timed out or was filtered, but the hop itself was identified.
                    # Treat as 100% loss for this probe.
                    packet_loss_percent = 100.0

                hop_data = {
                    "hop": hop_num,
                    "ip": current_hop_ip,
                    "rtt_ms": rtt_ms,
                    "packet_loss_percent": packet_loss_percent 
                }
                hop_details_list.append(hop_data)

                # Check if target is reached
                if not target_reached_flag and target_ip_resolved_early and current_hop_ip == target_ip_resolved_early:
                    target_reached_flag = True
                    print(f"{COLOR_GREEN}[+] Target {target_host} ({target_ip_resolved_early}) reached at hop {hop_num}.{COLOR_RESET}")

                # --- Findings Generation ---
                if rtt_ms and rtt_ms > 200: # High RTT threshold
                    add_finding_func(
                        managed_findings, SEVERITY_MEDIUM,
                        f"High RTT to {current_hop_ip} (Hop {hop_num}) for {target_host}",
                        f"RTT to {current_hop_ip} (hop {hop_num}) is {rtt_ms:.2f} ms when tracing {target_host}.",
                        "Investigate potential network congestion or issues at this hop. High latency can impact application performance."
                    )
                
                # Packet loss for -q 1 means the single probe was lost.
                if packet_loss_percent == 100.0:
                     # Avoid flagging the *target itself* if it's the one timing out, as this is covered by "target unreachable"
                     if not (target_reached_flag and current_hop_ip == target_ip_resolved_early) :
                        add_finding_func(
                            managed_findings, SEVERITY_MEDIUM,
                            f"Packet Loss/Timeout at Hop {hop_num} ({current_hop_ip}) for {target_host}",
                            f"Hop {hop_num} ({current_hop_ip}) for target {target_host} reported 100% packet loss or timed out for the probe.",
                            "This could indicate a firewall blocking probes, routing issues, ICMP de-prioritization, or an unresponsive hop. Consistent loss here can affect connectivity."
                        )
        
        managed_stats['network']['traceroute'][target_host]['hops'] = hop_details_list

        if not hop_details_list and not managed_stats['network']['traceroute'][target_host]['error']:
            no_hops_msg = "No hops were parsed from the traceroute output, though the command ran without explicit error. Output might be in an unexpected format or target is very close (e.g. localhost)."
            add_finding_func(managed_findings, SEVERITY_LOW, f"Traceroute to {target_host}: No Hops Parsed", no_hops_msg, f"Raw Output (first 300 chars): {stdout[:300]}")
            managed_stats['network']['traceroute'][target_host]['summary'] = no_hops_msg

        # Final check on target reachability
        if target_reached_flag:
            summary_msg = f"Target {target_host} ({target_ip_resolved_early}) was successfully reached in {len(hop_details_list)} hops."
            print(f"{COLOR_GREEN}{summary_msg}{COLOR_RESET}")
            managed_stats['network']['traceroute'][target_host]['summary'] = summary_msg
        elif hop_details_list: # Trace completed but target IP was not among the hops
            last_hop_info = hop_details_list[-1]
            summary_msg = f"Target {target_host} ({target_ip_resolved_early if target_ip_resolved_early else 'unresolved'}) was NOT explicitly reached. Traceroute ended at {last_hop_info['ip']} (hop {last_hop_info['hop']})."
            print(f"{COLOR_YELLOW}{summary_msg}{COLOR_RESET}")
            add_finding_func(
                managed_findings, SEVERITY_HIGH,
                f"Target {target_host} Unreachable or Last Hop Mismatch",
                summary_msg + (f" Target resolved to {target_ip_resolved_early}." if target_ip_resolved_early else " Target IP could not be pre-resolved."),
                "The target may be down, firewalled (blocking incoming probes or outgoing ICMP time exceeded messages from last router), or there might be a routing problem preventing the trace from reaching the destination."
            )
            managed_stats['network']['traceroute'][target_host]['summary'] = summary_msg
            managed_stats['network']['traceroute'][target_host]['error'] = "Target not reached" # Set a clear error status
        elif not managed_stats['network']['traceroute'][target_host]['error']: # No hops and no specific error from command execution
            # This case implies something went wrong if not caught before, e.g. no output but no stderr.
            summary_msg = f"Traceroute to {target_host} completed with no hops and no specific error reported by the command. Target reachability unknown."
            print(f"{COLOR_YELLOW}{summary_msg}{COLOR_RESET}")
            managed_stats['network']['traceroute'][target_host]['summary'] = summary_msg
            # Potentially add a generic finding if this state is undesirable
            add_finding_func(managed_findings, SEVERITY_LOW, f"Traceroute to {target_host}: Inconclusive", summary_msg, "Investigate traceroute execution and output.")


    except subprocess.TimeoutExpired:
        error_msg = f"Traceroute command timed out for {target_host} after 60 seconds."
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Traceroute Timeout", error_msg, f"Host: {target_host}, Command: {' '.join(command)}")
        managed_stats['network']['traceroute'][target_host]['error'] = "Command timed out"
        managed_stats['network']['traceroute'][target_host]['summary'] = error_msg
    except FileNotFoundError: 
        # This specific exception for Popen occurs if 'traceroute' executable is not found at all.
        error_msg = f"Traceroute command ('{command[0]}') not found. Please ensure 'traceroute' is installed and in the system's PATH."
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Traceroute Not Found", error_msg, f"Host: {target_host}")
        managed_stats['network']['traceroute'][target_host]['error'] = error_msg
        managed_stats['network']['traceroute'][target_host]['summary'] = error_msg
    except Exception as e:
        error_msg = f"An unexpected error occurred during traceroute to {target_host}: {type(e).__name__} - {e}"
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Traceroute Unexpected Error", str(e), f"Host: {target_host}, Command: {' '.join(command)}")
        managed_stats['network']['traceroute'][target_host]['error'] = str(e)
        managed_stats['network']['traceroute'][target_host]['summary'] = error_msg


def discover_dhcp_servers(managed_stats, managed_findings, add_finding_func, authorized_dhcp_servers_list=None):
    """
    Discovers DHCP servers on the local network segments using Nmap's 
    'broadcast-dhcp-discover' NSE script. It then compares discovered server IPs
    against a provided list of authorized DHCP servers to identify potential
    rogue DHCP servers.

    Methodology:
    1. Checks if Nmap is installed.
    2. Executes `sudo nmap --script broadcast-dhcp-discover -oX -` to find DHCP servers.
       This command requires root privileges to send broadcast probes and listen for responses.
    3. Parses the XML output from Nmap to extract details of DHCP offers received.
    4. Compares the 'Server Identifier' (DHCP server's IP) from each offer against
       the `authorized_dhcp_servers_list`.

    Args:
        managed_stats (Manager.dict): Shared dictionary to store statistics.
            Relevant keys:
            - `managed_stats['network']['dhcp_servers']`: List of dicts, each containing
              details of a discovered DHCP server offer (server_ip, interface, ip_offered, etc.).
            - `managed_stats['network']['dhcp_discovery_error']`: Stores error messages if
              the discovery process fails (e.g., Nmap not found, command error, timeout, XML parse error).
        managed_findings (Manager.list): Shared list to append findings.
        add_finding_func (function): Function to add a finding to `managed_findings`.
        authorized_dhcp_servers_list (list, optional): A list of IP addresses of known,
            authorized DHCP servers. If `None` or empty (default), any discovered DHCP
            server will be flagged with a higher severity or noted as unconfirmed.

    Findings Generated:
    - SEVERITY_CRITICAL ("Rogue DHCP Server Detected"): If a discovered DHCP server's IP
      is not in the `authorized_dhcp_servers_list`.
    - SEVERITY_INFO ("Authorized DHCP Server Found"): If a discovered server's IP matches
      an entry in `authorized_dhcp_servers_list`.
    - SEVERITY_LOW ("No DHCP Offers Received"): If the Nmap scan completes successfully
      but no DHCP offers are detected.
    - SEVERITY_INFO ("No DHCP Offers Parsed or Detected"): If Nmap runs but no valid DHCP
      details are parsed from its output.
    - SEVERITY_HIGH ("Nmap Not Found for DHCP Discovery"): If Nmap is not installed.
    - SEVERITY_HIGH ("Nmap DHCP Discovery Failed", "Nmap DHCP Discovery Timed Out",
      "Nmap DHCP XML Parse Error", "Nmap DHCP Discovery System Error"): For various
      Nmap execution or parsing failures.

    Requirements:
    - Nmap: Must be installed and in the system's PATH.
    - Root Privileges: The Nmap command used requires root privileges to function correctly.
      Guardian (or this script if run standalone) must be executed with `sudo`.
    """
    if authorized_dhcp_servers_list is None:
        authorized_dhcp_servers_list = []

    print(f"{COLOR_GREEN}[*] Discovering DHCP servers on the network...{COLOR_RESET}")

    # Initialize stats entries
    if 'network' not in managed_stats:
        managed_stats['network'] = {}
    managed_stats['network']['dhcp_servers'] = []
    managed_stats['network']['dhcp_discovery_error'] = None

    # 1. Check for Nmap installation
    try:
        nmap_check_process = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=10)
        if nmap_check_process.returncode != 0:
            error_msg = f"Nmap version check failed. Stderr: {nmap_check_process.stderr}"
            raise FileNotFoundError(error_msg) # Treat as if not found if version check fails oddly
    except FileNotFoundError:
        error_desc = "Nmap is required for DHCP server discovery but was not found in PATH."
        add_finding_func(managed_findings, SEVERITY_HIGH, "Nmap Not Found for DHCP Discovery",
                         error_desc, "Please install Nmap (e.g., 'sudo apt-get install nmap' or 'sudo yum install nmap').")
        managed_stats['network']['dhcp_discovery_error'] = error_desc
        print(f"{COLOR_RED}Error: {error_desc}{COLOR_RESET}")
        return
    except subprocess.TimeoutExpired:
        error_desc = "Nmap --version command timed out. Cannot confirm Nmap installation."
        add_finding_func(managed_findings, SEVERITY_HIGH, "Nmap Check Timed Out",
                         error_desc, "Ensure Nmap is installed and accessible. If issues persist, check system load.")
        managed_stats['network']['dhcp_discovery_error'] = error_desc
        print(f"{COLOR_RED}Error: {error_desc}{COLOR_RESET}")
        return


    # 2. Construct Nmap command
    # The script 'broadcast-dhcp-discover' sends a DHCPDISCOVER broadcast.
    # -oX - outputs XML to stdout.
    # Nmap needs root/sudo for this script.
    # The script itself has a default timeout of 10s for waiting for offers.
    # We add an overall timeout for the subprocess.
    nmap_command = ["sudo", "nmap", "--script", "broadcast-dhcp-discover", "-oX", "-"]
    # Using --host-timeout for Nmap itself can be tricky with broadcast scripts.
    # The script argument broadcast-dhcp-discover.timeout can be used if needed:
    # nmap_command.extend(["--script-args", "broadcast-dhcp-discover.timeout=5000"]) # 5000ms = 5s

    # 3. Execute Nmap command
    print(f"{COLOR_GREEN}[*] Running Nmap DHCP discovery: {' '.join(nmap_command)}{COLOR_RESET}")
    try:
        # Increased timeout as DHCP discovery can sometimes take a moment for multiple offers.
        process = subprocess.run(nmap_command, capture_output=True, text=True, timeout=45, check=False)
        
        if process.returncode != 0:
            # Nmap might return non-zero for various reasons, even if some output is generated.
            # Check stderr for critical errors.
            # Warnings like "WARNING: Service 161/udp on 192.168.X.Y is already bound. Skipping." are common and OK.
            # "Failed to resolve/send to host: <interface_name>" can also appear if an interface is down, not necessarily fatal.
            # Look for more specific errors like "SCRIPT ENGINE FAILED" or permission issues.
            stderr_output = process.stderr.strip()
            if "permission denied" in stderr_output.lower() or "requires root privileges" in stderr_output.lower():
                 error_msg = f"Nmap DHCP discovery failed due to permission issues. Ensure 'sudo' is used correctly and has permissions. Stderr: {stderr_output}"
            elif "script engine failed" in stderr_output.lower():
                 error_msg = f"Nmap script engine failed for DHCP discovery. Stderr: {stderr_output}"
            else:
                # Generic failure, could be partial results. Log stderr but proceed to parse stdout if available.
                error_msg = f"Nmap DHCP discovery finished with return code {process.returncode}. Stderr: {stderr_output}"
                print(f"{COLOR_YELLOW}Warning: {error_msg}{COLOR_RESET}") 
                # Don't set dhcp_discovery_error yet, as there might be partial XML data.

            # If stdout is empty and there was an error, it's a definite failure to record.
            if not process.stdout.strip() and error_msg: # Check error_msg is defined
                 managed_stats['network']['dhcp_discovery_error'] = error_msg
                 add_finding_func(managed_findings, SEVERITY_HIGH, "Nmap DHCP Discovery Failed",
                                 error_msg, "Check Nmap installation, permissions (sudo), and network interfaces. Ensure Nmap can bind to necessary sockets.")
                 print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
                 # If no stdout, return here. If there is stdout, try to parse it.
                 return


        nmap_xml_output = process.stdout.strip()
        if not nmap_xml_output:
            if not managed_stats['network'].get('dhcp_discovery_error'): # If no specific error was already set
                error_msg = "Nmap DHCP discovery produced no XML output."
                managed_stats['network']['dhcp_discovery_error'] = error_msg
                add_finding_func(managed_findings, SEVERITY_MEDIUM, "Nmap DHCP Discovery No Output",
                                error_msg, "Verify Nmap command execution and that DHCP servers are active on the network segments if expected.")
            print(f"{COLOR_YELLOW}Warning: Nmap DHCP discovery produced no XML output.{COLOR_RESET}")
            return

        # Phase 2 (XML Parsing and Findings) will go here.
        # For now, just storing the raw XML if successful.
        # managed_stats['network']['dhcp_raw_xml'] = nmap_xml_output 
        # print(f"{COLOR_GREEN}Nmap DHCP discovery completed. XML output captured. Parsing to be implemented.{COLOR_RESET}")


    except subprocess.TimeoutExpired:
        error_msg = f"Nmap DHCP discovery command ('{' '.join(nmap_command)}') timed out after 45 seconds."
        managed_stats['network']['dhcp_discovery_error'] = error_msg
        add_finding_func(managed_findings, SEVERITY_HIGH, "Nmap DHCP Discovery Timed Out",
                         error_msg, "The network might be too large, too many offers, or Nmap is hanging. Consider adjusting timeouts or checking network conditions.")
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        return
    except Exception as e: # Catch other unexpected errors like issues with subprocess.run itself
        error_msg = f"An unexpected error occurred during Nmap DHCP discovery: {type(e).__name__} - {e}"
        managed_stats['network']['dhcp_discovery_error'] = error_msg
        add_finding_func(managed_findings, SEVERITY_HIGH, "Nmap DHCP Discovery System Error",
                         error_msg, "Review system logs and ensure the script environment is stable.")
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        return

    # --- Phase 2: XML Parsing and Findings ---
    import xml.etree.ElementTree as ET # Added import

    discovered_servers_details = []
    try:
        root = ET.fromstring(nmap_xml_output)
        for host_element in root.findall('host'):
            # The 'broadcast-dhcp-discover' script output is usually in <hostscript><script output="..."/>
            # Sometimes it can be directly under <script output="..."/> if nmap doesn't associate it with a specific host IP (e.g. when run without host discovery -n)
            # We will check both hostscript/script and direct script elements under root if no hosts are found.

            hostscripts = host_element.find('hostscript')
            if hostscripts is not None:
                scripts = hostscripts.findall('script')
            else: # Check for scripts directly under root if no hostscript (less common for this specific script)
                scripts = host_element.findall('script') # Actually, script is usually child of host or hostscript

            for script_element in scripts:
                if script_element.get('id') == 'broadcast-dhcp-discover':
                    script_output_text = script_element.get('output')
                    if script_output_text:
                        # The output is a block of text. We need to parse this.
                        # Example: "\n  Interface: eth0\n    IP Offered: 192.168.1.100\n    DHCP Message Type: DHCPOFFER\n    Server Identifier: 192.168.1.1\n    ..."
                        # Each DHCP offer can be a "Response X of Y" block or similar.
                        # For simplicity, let's assume one offer per script output block for now, or parse distinct offers.
                        # Nmap's output might group multiple offers if received from different interfaces or servers.
                        
                        # Split into "Response X of Y" blocks if they exist or process as a whole
                        # A simpler approach is to look for "Server Identifier:" which is key.
                        # Multiple offers might be in the same output string, often separated by "Response X of Y:"
                        # Let's process the output for key fields.

                        server_details = {}
                        
                        # Regex patterns for parsing the script output text
                        # These need to be robust. Using re.MULTILINE for searching.
                        # Server Identifier is the actual DHCP server's IP
                        server_id_match = re.search(r"Server Identifier:\s*([0-9.]+)", script_output_text, re.IGNORECASE)
                        if server_id_match:
                            server_details['server_ip'] = server_id_match.group(1).strip()
                        else:
                            # If no Server Identifier, this block might not be a valid DHCP offer.
                            # However, nmap might report the source IP of the packet as the host address.
                            # Let's try to get the address from the <address> tag of the <host> element if server_id is missing.
                            # This is a fallback, Server Identifier is preferred.
                            address_element = host_element.find("address[@addrtype='ipv4']")
                            if address_element is not None and address_element.get('addr'):
                                server_details['server_ip_fallback'] = address_element.get('addr')
                                # If we use this fallback, we should note it.
                                # For now, we prioritize Server Identifier. If missing, we might skip or flag this entry.
                                if not server_details.get('server_ip'): # Only use if primary server_ip is not found
                                    print(f"{COLOR_YELLOW}Warning: Could not find 'Server Identifier' in DHCP offer. Using host address {server_details['server_ip_fallback']} as potential server IP.{COLOR_RESET}")
                                    server_details['server_ip'] = server_details['server_ip_fallback']


                        if not server_details.get('server_ip'):
                            # If still no server_ip, this script output block is not useful for identifying a DHCP server IP.
                            print(f"{COLOR_YELLOW}Warning: Skipping a DHCP script output block as no Server Identifier or host IP found. Output: {script_output_text[:150]}...{COLOR_RESET}")
                            continue

                        interface_match = re.search(r"Interface:\s*(\S+)", script_output_text, re.IGNORECASE)
                        if interface_match: server_details['interface'] = interface_match.group(1).strip()
                        
                        ip_offered_match = re.search(r"IP Offered:\s*([0-9.]+)", script_output_text, re.IGNORECASE)
                        if ip_offered_match: server_details['ip_offered'] = ip_offered_match.group(1).strip()

                        subnet_mask_match = re.search(r"Subnet Mask:\s*([0-9.]+)", script_output_text, re.IGNORECASE)
                        if subnet_mask_match: server_details['subnet_mask'] = subnet_mask_match.group(1).strip()
                        
                        router_match = re.search(r"Router:\s*([0-9.,\s]+)", script_output_text, re.IGNORECASE) # Can be multiple
                        if router_match: server_details['router'] = router_match.group(1).strip()

                        dns_match = re.search(r"Domain Name Server:\s*([0-9.,\s]+)", script_output_text, re.IGNORECASE) # Can be multiple
                        if dns_match: server_details['dns_servers'] = dns_match.group(1).strip()

                        lease_time_match = re.search(r"IP Address Lease Time:\s*(.+)", script_output_text, re.IGNORECASE)
                        if lease_time_match: server_details['lease_time'] = lease_time_match.group(1).strip()
                        
                        dhcp_type_match = re.search(r"DHCP Message Type:\s*(\S+)", script_output_text, re.IGNORECASE)
                        if dhcp_type_match: server_details['dhcp_message_type'] = dhcp_type_match.group(1).strip()
                        
                        # Add other fields as necessary
                        discovered_servers_details.append(server_details)
        
        # If root.tag is 'nmaprun' but no 'host' elements, check for script output directly under 'runstats' or 'taskbegin/taskend' (less likely for this script)
        # This path is typically for global script results not tied to a host.
        # However, broadcast-dhcp-discover usually reports per "host" which is the interface it used or received on.
        # The above loop should cover most cases. If it doesn't, the XML structure from Nmap for this script needs closer inspection.
        # For now, we assume the host-based iteration is sufficient.

    except ET.ParseError as e:
        error_msg = f"Failed to parse Nmap XML output for DHCP discovery. Error: {e}. XML (first 500 chars): {nmap_xml_output[:500]}"
        managed_stats['network']['dhcp_discovery_error'] = error_msg
        add_finding_func(managed_findings, SEVERITY_HIGH, "Nmap DHCP XML Parse Error",
                         error_msg, "Check Nmap's output format or if the XML is corrupted. Ensure Nmap version is compatible.")
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        return # Cannot proceed if XML is unparseable

    if not discovered_servers_details:
        # This means Nmap ran, produced XML, but we couldn't find any DHCP server details from the script output.
        # Or the script found no active DHCP offers.
        if not managed_stats['network'].get('dhcp_discovery_error'): # Only if no prior critical error
            info_msg = "No DHCP offers were successfully parsed from the Nmap scan. This could mean no active DHCP servers responded on the broadcast segments, or the Nmap script did not detect any."
            add_finding_func(managed_findings, SEVERITY_INFO, # Changed from LOW to INFO as it's common if no DHCP on segment
                             "No DHCP Offers Parsed or Detected", info_msg,
                             "If a DHCP server is expected, verify its operation and network reachability. Ensure Guardian has necessary permissions for Nmap broadcast scans.")
            managed_stats['network']['dhcp_servers_summary'] = info_msg # Store a summary
        print(f"{COLOR_YELLOW}Info: No DHCP server details were parsed from Nmap output.{COLOR_RESET}")
        # We don't return here, as we want to store the (empty) discovered_servers_details list.
    
    managed_stats['network']['dhcp_servers'] = discovered_servers_details

    # 6. Rogue DHCP Detection
    if not discovered_servers_details and not managed_stats['network'].get('dhcp_discovery_error'):
        # This finding is slightly redundant with the "No DHCP Offers Parsed or Detected" INFO finding above,
        # but more direct as per original requirements.
        # Consider keeping only one. For now, as per step 7.
        add_finding_func(managed_findings, SEVERITY_LOW, "No DHCP Offers Received",
                         "No DHCP offers were received during the broadcast discovery scan.",
                         "Verify DHCP server availability if one is expected on this network segment.")
    
    for server in discovered_servers_details:
        server_ip = server.get('server_ip')
        if not server_ip: # Should have been caught earlier, but as a safeguard
            continue

        interface_info = f"on interface {server.get('interface', 'N/A')}" if server.get('interface') else "on an undetermined interface"
        
        if server_ip not in authorized_dhcp_servers_list:
            desc = (f"A potentially rogue DHCP server with IP {server_ip} was detected {interface_info}. "
                    f"It is not in the authorized list: {authorized_dhcp_servers_list if authorized_dhcp_servers_list else '(empty)'}. "
                    f"Offered IP: {server.get('ip_offered', 'N/A')}, Subnet: {server.get('subnet_mask', 'N/A')}, "
                    f"Router: {server.get('router', 'N/A')}, DNS: {server.get('dns_servers', 'N/A')}.")
            add_finding_func(managed_findings, SEVERITY_CRITICAL, "Rogue DHCP Server Detected",
                             desc,
                             "Investigate this server immediately. Unauthorized DHCP servers can cause network disruptions, assign incorrect network configurations, or be used for man-in-the-middle attacks. Disconnect the device from the network if confirmed rogue.")
        else:
            desc = (f"Authorized DHCP server {server_ip} responded {interface_info}. "
                    f"Offered IP: {server.get('ip_offered', 'N/A')}, Subnet: {server.get('subnet_mask', 'N/A')}, "
                    f"Router: {server.get('router', 'N/A')}, DNS: {server.get('dns_servers', 'N/A')}.")
            add_finding_func(managed_findings, SEVERITY_INFO, "Authorized DHCP Server Found", desc)

    print(f"{COLOR_GREEN}[+] DHCP discovery and analysis complete. Found {len(discovered_servers_details)} DHCP offer(s).{COLOR_RESET}")
