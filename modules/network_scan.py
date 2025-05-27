#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Network Scanning (Interfaces, Listening Ports, Traceroute)
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