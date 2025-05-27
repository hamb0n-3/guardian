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
    if 'network' not in managed_stats:
        managed_stats['network'] = {} 
    if 'traceroute_results' not in managed_stats['network']:
        managed_stats['network']['traceroute_results'] = {}
        
    system = platform.system()
    
    # Regex definitions
    # Linux/macOS: captures hop, IP, and the RTT string (e.g., "0.300 ms  0.250 ms  0.200 ms" or "* 0.800 ms *")
    linux_hop_regex = re.compile(r"^\s*(\d+)\s+([\d\.]+)\s+((?:[\d\.]+\s+ms|\*)\s*(?:[\d\.]+\s+ms|\*){0,2})")
    # Windows: captures hop, RTT string, and IP
    windows_hop_regex = re.compile(r"^\s*(\d+)\s+((?:<?\d+\s+ms|\*)\s+(?:<?\d+\s+ms|\*)\s+(?:<?\d+\s+ms|\*))\s+([\d\.]+)")
    # Windows timeout line: "  1     *        *        *     Request timed out."
    windows_timeout_regex = re.compile(r"^\s*(\d+)\s+(\*\s+\*\s+\*|\*\s+Request timed out\.|Request timed out\.)")


    if system == "Windows":
        command = ["tracert", "-d", "-w", "1000", target_host] # -w 1000ms timeout for each reply
    else: # Linux/macOS
        # -q 3 (probes per hop), -n (no reverse DNS in command output), -w 1 (wait 1 sec for reply)
        # Some traceroute versions might use -W for timeout per probe in seconds (float)
        # Using a common set of flags. Adjust if needed for specific traceroute versions.
        command = ["traceroute", "-q", "3", "-n", "-w", "1", target_host]


    success, output = run_command(command, timeout=90) # Increased timeout for 3 probes with 1s wait each + overhead

    if not success or not output:
        error_msg = f"Traceroute command failed or returned no output for {target_host}."
        if output: error_msg += f" Output: {output.strip()}"
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Traceroute Execution Failed", error_msg, f"Verify '{command[0]}' is installed and {target_host} is reachable.")
        managed_stats['network']['traceroute_results'][target_host] = [{'error': error_msg}]
        return

    hops_list = []
    output_lines = output.splitlines()
    previous_avg_rtt = 0.0

    for line in output_lines:
        line = line.strip()
        hop_num_str, ip_address, rtt_string = None, None, None
        is_timeout_line = False

        if system == "Windows":
            match = windows_hop_regex.match(line)
            if match:
                hop_num_str, rtt_string, ip_address = match.groups()
            else:
                timeout_match_win = windows_timeout_regex.match(line)
                if timeout_match_win:
                    hop_num_str = timeout_match_win.group(1)
                    ip_address = "Timeout"
                    rtt_string = "* * *" # Standardize timeout RTT string
                    is_timeout_line = True
        else: # Linux/macOS
            match = linux_hop_regex.match(line)
            if match:
                hop_num_str, ip_address, rtt_string = match.groups()
            else: # Check for lines like " 2  * * *" (all probes timeout)
                timeout_match_nix = re.match(r"^\s*(\d+)\s+(\*\s*){1,3}$", line)
                if timeout_match_nix:
                    hop_num_str = timeout_match_nix.group(1)
                    ip_address = "Timeout"
                    rtt_string = "* * *" # Standardize
                    is_timeout_line = True
        
        if hop_num_str:
            try:
                hop_num = int(hop_num_str)
                rtt_stats = _parse_rtt_string_and_calculate_stats(rtt_string, system)
                
                hostname = ip_address
                if ip_address != "Timeout":
                    try:
                        hostname, _, _ = socket.gethostbyaddr(ip_address)
                    except socket.herror: pass # Keep IP as hostname
                    except Exception as e_dns:
                        print(f"{COLOR_YELLOW}Warning: Reverse DNS for {ip_address} failed: {e_dns}{COLOR_RESET}")

                hop_info = {
                    'hop': hop_num, 'ip': ip_address, 'hostname': hostname,
                    'rtts_raw': rtt_stats['rtts_parsed'],
                    'min_rtt': rtt_stats['min_rtt'], 'max_rtt': rtt_stats['max_rtt'],
                    'avg_rtt': rtt_stats['avg_rtt'], 'packet_loss': rtt_stats['packet_loss_percentage']
                }
                hops_list.append(hop_info)

                rtt_summary = f"Avg RTT: {rtt_stats['avg_rtt']:.2f}ms" if rtt_stats['avg_rtt'] != float('inf') else "Avg RTT: N/A"
                loss_summary = f"Loss: {rtt_stats['packet_loss_percentage']:.0f}%"
                finding_desc = f"IP: {ip_address} (Hostname: {hostname}), {rtt_summary}, {loss_summary}"
                add_finding_func(managed_findings, SEVERITY_INFO, f"Traceroute to {target_host} - Hop {hop_num}", finding_desc)

                if rtt_stats['avg_rtt'] != float('inf'): # Check if avg_rtt is valid
                    if rtt_stats['avg_rtt'] > 200:
                        add_finding_func(managed_findings, SEVERITY_LOW, f"High Latency Hop: {target_host} - Hop {hop_num}",
                                         f"Hop {hop_num} ({ip_address}) has an average RTT of {rtt_stats['avg_rtt']:.2f} ms.")
                    if previous_avg_rtt > 0 and rtt_stats['avg_rtt'] > (previous_avg_rtt * 2 + 10):
                         add_finding_func(managed_findings, SEVERITY_LOW, f"Significant RTT Jump: {target_host} - Hop {hop_num}",
                                         f"RTT jumped from {previous_avg_rtt:.2f}ms (Hop {hop_num-1}) to {rtt_stats['avg_rtt']:.2f}ms (Hop {hop_num}).")
                    previous_avg_rtt = rtt_stats['avg_rtt']
                elif rtt_stats['packet_loss_percentage'] == 100 and ip_address == "Timeout": # If all probes lost and IP is timeout
                    previous_avg_rtt = float('inf') # Reset for next hop comparison, or mark as very high
                
                if rtt_stats['packet_loss_percentage'] > 10: # Threshold for packet loss finding
                     add_finding_func(managed_findings, SEVERITY_MEDIUM, f"Packet Loss at Hop: {target_host} - Hop {hop_num}",
                                     f"Hop {hop_num} ({ip_address}) has {rtt_stats['packet_loss_percentage']:.0f}% packet loss.")

            except ValueError as ve:
                print(f"{COLOR_YELLOW}Warning: Could not parse hop number for line: '{line}'. Error: {ve}{COLOR_RESET}")
            except Exception as e_parse:
                print(f"{COLOR_RED}Error parsing hop details for line '{line}': {e_parse}{COLOR_RESET}")
                # Add a placeholder if critical info missing but hop_num was parsed
                if hop_num_str:
                    hops_list.append({'hop': int(hop_num_str), 'ip': ip_address or 'Parse Error', 'hostname': 'Parse Error', 
                                      'min_rtt': 'N/A', 'max_rtt': 'N/A', 'avg_rtt': 'N/A', 'packet_loss': 'N/A', 'rtts_raw': [rtt_string]})


    if not hops_list and output:
        add_finding_func(managed_findings, SEVERITY_LOW, f"Traceroute Parsing Incomplete for {target_host}",
                         f"Could not parse any hops from traceroute output. Raw output (first 200 chars): {output[:200]}...",
                         "Review module's regex if valid hops were present in output.")
    elif hops_list:
        add_finding_func(managed_findings, SEVERITY_INFO, f"Traceroute to {target_host} Completed",
                         f"{len(hops_list)} hops identified and analyzed.", f"Path to {target_host} has been recorded with RTT/loss stats.")
    
    managed_stats['network']['traceroute_results'][target_host] = hops_list
    print(f"{COLOR_GREEN}[+] Traceroute to {target_host} finished.{COLOR_RESET}")


def _parse_rtt_string_and_calculate_stats(rtt_string, os_type, probes_sent=3):
    """
    Parses a string of RTT values (e.g., "10 ms  *  12 ms") and calculates stats.
    Returns a dict with min_rtt, max_rtt, avg_rtt, packet_loss_percentage, and raw rtts.
    """
    rtts = []
    rtts_parsed_for_storage = [] # Store what was parsed, including '*'
    packets_lost = 0

    parts = rtt_string.strip().split()
    
    # Windows tracert might group "<1" with "ms" as "<1 ms" or just be "*"
    # Linux traceroute typically has "0.300 ms" or "*"
    
    # Temporary list to hold values before associating with 'ms' or '*'
    temp_values = []
    skip_next = False
    for i, part in enumerate(parts):
        if skip_next:
            skip_next = False
            continue
        
        if part == "*":
            temp_values.append("*")
        elif part.endswith("ms"):
            val_str = part[:-2].strip() # remove "ms"
            if val_str == "<1":
                temp_values.append(0.5) # Represent <1 ms as 0.5 ms
            else:
                try: temp_values.append(float(val_str))
                except ValueError: temp_values.append("*") # If conversion fails, treat as loss
        elif part == "<1" and i + 1 < len(parts) and parts[i+1] == "ms": # Handle "<1 ms"
            temp_values.append(0.5)
            skip_next = True # Skip "ms" part
        elif part.lower() == "request" and i + 1 < len(parts) and parts[i+1].lower() == "timed": # "Request timed out"
            temp_values.append("*")
            skip_next = True # Skip "timed"
            if i + 2 < len(parts) and parts[i+2].lower() == "out.": # Skip "out."
                skip_next = True # This logic is getting complex, simpler split by 'ms' and '*' might be better for some cases
        else: # Assume it's a numeric part of an RTT or unhandled, try to float if it's a number
            try: 
                # This case is tricky, if `traceroute` output is just numbers separated by spaces without 'ms'
                # For now, the regex is designed to capture 'ms' or '*' with the values.
                # So, this 'else' is less likely to be hit with current regexes if they capture units.
                # If it IS hit, and it's a number, it's an RTT. If not, it's part of something unexpected.
                # float_val = float(part)
                # temp_values.append(float_val)
                pass # Let regexes handle units. If unitless numbers appear, current logic might miss them.
            except ValueError:
                pass # Ignore parts that are not '*' or numeric with 'ms'

    # Ensure we account for the standard number of probes if parts are missing (e.g. less than 3 RTTs shown)
    # The regex for Linux is already designed to capture up to 3 RTTs or '*'
    # The regex for Windows also captures 3 RTT slots or '*'
    
    for val in temp_values:
        if val == "*":
            packets_lost += 1
            rtts_parsed_for_storage.append("*")
        else:
            rtts.append(val)
            rtts_parsed_for_storage.append(val)
            
    # If fewer results than probes_sent, assume remaining are lost (common if traceroute stops early for a hop)
    # This needs to be handled carefully; if the command itself limits probes (e.g. -q 1), this is wrong.
    # Assuming `probes_sent` is the actual number of attempts for that line.
    # The regexes are built for 3 probes. If traceroute output format changes, this needs adjustment.
    # For now, derive probes_sent from elements parsed if it's less than 3, but aim for 3.
    
    actual_probes_represented = len(rtts_parsed_for_storage)
    if actual_probes_represented < probes_sent:
        packets_lost += (probes_sent - actual_probes_represented)
        rtts_parsed_for_storage.extend(["*"] * (probes_sent - actual_probes_represented))


    if not rtts: # All packets lost for this hop
        min_rtt, max_rtt, avg_rtt = float('inf'), float('inf'), float('inf')
    else:
        min_rtt = min(rtts)
        max_rtt = max(rtts)
        avg_rtt = sum(rtts) / len(rtts)

    packet_loss_percentage = (packets_lost / probes_sent) * 100 if probes_sent > 0 else 0

    return {
        'rtts_parsed': rtts_parsed_for_storage, # List of floats or '*'
        'min_rtt': min_rtt,
        'max_rtt': max_rtt,
        'avg_rtt': avg_rtt,
        'packets_lost': packets_lost,
        'probes_sent': probes_sent, # Reflects the number of probes we attempted to parse
        'packet_loss_percentage': packet_loss_percentage
    }