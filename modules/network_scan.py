#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Network Scanning (Interfaces, Listening Ports)
"""

import socket
import psutil
import platform
import re
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH,
    run_command # Assuming run_command is available in utils
)

def get_network_interfaces(managed_stats, managed_findings, add_finding_func):
    """Gathers network interface info, storing results in managed dicts."""
    print(f"{COLOR_GREEN}[*] Gathering Network Interface Information...{COLOR_RESET}")
    # Ensure base network key exists in managed stats
    if 'network' not in managed_stats:
        # Using a standard dict here is okay if only this process modifies 'network' sub-keys
        # If multiple processes might write to 'network', use manager.dict()
        managed_stats['network'] = {} 

    interfaces_local = {}
    try:
        all_interfaces = psutil.net_if_addrs()
        if not all_interfaces:
             add_finding_func(managed_findings, SEVERITY_MEDIUM, "No Network Interfaces Found", "psutil could not detect any network interfaces.")
             managed_stats['network']['interfaces_error'] = "No interfaces detected by psutil"
             return

        for name, snicaddrs in all_interfaces.items():
            interface_info = {'addresses': []} # Store locally first
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
        
        # Assign the collected interfaces to the managed stats dict
        # Note: If another process modifies managed_stats['network'], potential race condition
        # It might be safer to initialize managed_stats['network'] = manager.dict() in main
        # or ensure only one process writes to the 'network' key at this level.
        # For now, assuming sequential modification or separate keys is sufficient.
        current_network_stats = managed_stats['network']
        current_network_stats['interfaces'] = interfaces_local
        managed_stats['network'] = current_network_stats # Reassign to sync

    except Exception as e:
        print(f"{COLOR_RED}Error gathering network interface info: {e}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Network Interface Error", f"Failed to gather network interface info: {e}")
        # Store error in stats
        current_network_stats = managed_stats.get('network', {})
        current_network_stats['interfaces_error'] = str(e)
        managed_stats['network'] = current_network_stats

def get_listening_ports(managed_stats, managed_findings, add_finding_func):
    """Gathers listening port info, storing results in managed dicts."""
    print(f"{COLOR_GREEN}[*] Gathering Listening Ports...{COLOR_RESET}")
    if 'network' not in managed_stats:
        managed_stats['network'] = {} # Initialize if interfaces didn't run/failed

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

                # --- Basic Analysis & Findings ---
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
                if port_info['local_port'] == 21:
                     add_finding_func(managed_findings, SEVERITY_HIGH, "FTP Server Detected", f"Port 21 (FTP) open (Process: {port_info['process_name']}). FTP is insecure.", "Use SFTP/FTPS instead. Disable FTP if not essential.")
                if port_info['local_port'] == 23:
                     add_finding_func(managed_findings, SEVERITY_HIGH, "Telnet Server Detected", f"Port 23 (Telnet) open (Process: {port_info['process_name']}). Telnet is insecure.", "Use SSH instead. Disable Telnet if not essential.")
                if port_info['local_port'] == 80 and port_info['local_addr'] != "127.0.0.1" and port_info['local_addr'] != "::1":
                     add_finding_func(managed_findings, SEVERITY_MEDIUM, "Unencrypted HTTP Service Detected", f"Port 80 (HTTP) open on non-localhost ({port_info['local_addr']}) (Process: {port_info['process_name']}).", "Use HTTPS (port 443) for encrypted web traffic.")

    except psutil.AccessDenied:
         warning_msg = "Access denied retrieving network connection details. Run as root for full info."
         print(f"{COLOR_YELLOW}Warning: {warning_msg}{COLOR_RESET}")
         add_finding_func(managed_findings, SEVERITY_LOW, "Network Scan Permissions Issue", warning_msg)
    except Exception as e:
        error_msg = f"Failed to gather listening port info: {e}"
        print(f"{COLOR_RED}Error gathering listening ports: {e}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Listening Port Error", error_msg)
        # Store error in stats
        current_network_stats = managed_stats.get('network', {})
        current_network_stats['listening_ports_error'] = str(e)
        managed_stats['network'] = current_network_stats

    # Update managed stats - carefully handle potential concurrent access if needed
    current_network_stats = managed_stats.get('network', {})
    current_network_stats['listening_ports'] = listening_ports_local # Store collected list
    current_network_stats['listening_ports_count'] = listening_count
    managed_stats['network'] = current_network_stats # Reassign to sync 

def trace_route_to_target(managed_stats, managed_findings, add_finding_func, target_host):
    """Performs a traceroute to the target host."""
    print(f"{COLOR_GREEN}[*] Starting traceroute to {target_host}...{COLOR_RESET}")

    # Ensure 'network' and 'traceroute_results' keys exist in managed_stats.
    # This is ideally prepared by the caller (wrapper in guardian.py)
    # For robustness, check and initialize if absolutely necessary, though this might not be multiprocess-safe if not managed dicts
    if 'network' not in managed_stats:
        managed_stats['network'] = {} # This should be a manager.dict() if created here
    if 'traceroute_results' not in managed_stats['network']:
        managed_stats['network']['traceroute_results'] = {} # This should be a manager.dict() if created here
        
    traceroute_results_for_target = [] # Local list to store hops

    system = platform.system()
    if system == "Windows":
        command = ["tracert", "-d", target_host]
        # Regex for Windows: extracts hop number and IP. Example: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
        # It should capture "  1" and "192.168.1.1"
        # More robust regex: Skip lines with '*' for timeouts or lines with "Trace complete."
        hop_regex = re.compile(r"^\s*(\d+)\s+.*?\s+([\d\.]+)\s*$")
    else: # Linux/macOS
        command = ["traceroute", "-n", target_host]
        # Regex for Linux: extracts hop number and IP. Example: " 1  192.168.1.1  0.300 ms  0.250 ms  0.200 ms"
        # It should capture " 1" and "192.168.1.1"
        hop_regex = re.compile(r"^\s*(\d+)\s+([\d\.]+)\s+.*")

    # Use a timeout for run_command, e.g., 60 seconds
    # The run_command utility is expected to return a tuple (success_boolean, output_string)
    success, output = run_command(command, timeout=60) 

    if not success or not output:
        error_msg = f"Traceroute command failed or returned no output for {target_host}."
        if output: # If there's some output (e.g. error message from command itself)
            error_msg += f" Output: {output.strip()}"
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Traceroute Execution Failed", error_msg, f"Verify '{command[0]}' is installed and {target_host} is reachable.")
        managed_stats['network']['traceroute_results'][target_host] = [{'error': error_msg}]
        return

    hops_list = []
    output_lines = output.splitlines()

    for line in output_lines:
        line = line.strip()
        match = hop_regex.match(line)
        if match:
            hop_num_str, ip_address = match.groups()
            hop_num = int(hop_num_str)
            
            hostname = ip_address # Default to IP if resolution fails
            try:
                # Attempt reverse DNS lookup with a timeout (socket.gethostbyaddr doesn't have direct timeout)
                # This can be slow. Consider making it optional or handling timeouts carefully.
                # For now, basic attempt:
                hostname, _, _ = socket.gethostbyaddr(ip_address)
            except socket.herror:
                pass # Keep hostname as IP address
            except Exception as e: # Catch other potential errors during resolution
                print(f"{COLOR_YELLOW}Warning: Reverse DNS lookup for {ip_address} failed: {e}{COLOR_RESET}")
                pass


            hop_info = {'hop': hop_num, 'ip': ip_address, 'hostname': hostname}
            hops_list.append(hop_info)
            
            add_finding_func(
                managed_findings,
                SEVERITY_INFO,
                f"Traceroute to {target_host} - Hop {hop_num}",
                f"IP: {ip_address} (Hostname: {hostname})",
                "Review route for unexpected or suspicious hops."
            )
        elif "*" in line and "Request timed out" not in line and "Trace complete" not in line: # Common timeout indicator
             # Try to get hop number if available (some traceroutes print " 1  * * *")
            timeout_match = re.match(r"^\s*(\d+)\s+\*\s+\*\s+\*", line)
            if timeout_match:
                hop_num_str = timeout_match.group(1)
                hop_num = int(hop_num_str)
                hops_list.append({'hop': hop_num, 'ip': 'Timeout', 'hostname': 'Timeout'})
                add_finding_func(
                    managed_findings,
                    SEVERITY_INFO,
                    f"Traceroute to {target_host} - Hop {hop_num}",
                    "Request timed out for this hop.",
                    "Timeouts can indicate filtering or unresponsive devices."
                )


    if not hops_list and output: # If regex failed to parse anything but there was output
        add_finding_func(managed_findings, SEVERITY_LOW, f"Traceroute Parsing Incomplete for {target_host}",
                         f"Could not parse any hops from traceroute output. Raw output: {output[:200]}...", # Show first 200 chars
                         "Review module's regex if valid hops were present in output.")
    elif hops_list:
        add_finding_func(
            managed_findings,
            SEVERITY_INFO,
            f"Traceroute to {target_host} Completed",
            f"{len(hops_list)} hops identified.",
            f"Path to {target_host} has been recorded."
        )
    
    # Store the list of hop dicts
    # This assumes managed_stats['network']['traceroute_results'] is a managed dict
    managed_stats['network']['traceroute_results'][target_host] = hops_list

    print(f"{COLOR_GREEN}[+] Traceroute to {target_host} finished.{COLOR_RESET}")