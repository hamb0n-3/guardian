#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Local Network Traffic Analyzer
"""

import psutil
import socket
import ssl
import http.client # For HTTP check
import platform # For OS check
import re # For parsing ss output
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, # Added SEVERITY_LOW
    run_command # Ensure run_command is imported
)

def analyze_local_traffic(managed_stats, managed_findings, add_finding_func):
    """
    Analyzes local network traffic (active connections) using psutil.
    Focuses on established ingress/egress connections.
    """
    print(f"{COLOR_GREEN}[*] Analyzing Local Network Traffic (Entry/Exit Points)...{COLOR_RESET}")

    traffic_stats = {
        'active_connections_count': 0,
        'tcp_connections': 0,
        'udp_connections': 0,
        'connection_details': [],
        'errors': []
    }

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        msg = "Access Denied: Cannot retrieve network connections. Run as root for full details."
        print(f"{COLOR_RED}Error: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Local Traffic Analysis Error", msg, "Run Guardian with root privileges.")
        traffic_stats['errors'].append(msg)
        managed_stats['local_traffic'] = traffic_stats
        return
    except Exception as e:
        msg = f"Failed to retrieve network connections: {e}"
        print(f"{COLOR_RED}Error: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Local Traffic Analysis Error", msg)
        traffic_stats['errors'].append(str(e))
        managed_stats['local_traffic'] = traffic_stats
        return

    active_connections_count = 0

    for conn in connections:
        # Focus on connections with a remote address, indicating active/established or similar state
        if not conn.raddr:  # raddr is empty for listening sockets
            continue
        
        # If raddr is present but port is 0, it might be an odd state, skip for now or log if needed.
        # Typically, established connections have raddr.port != 0.
        if conn.raddr and conn.raddr.port == 0:
            continue

        active_connections_count += 1
        
        conn_detail = {
            'fd': conn.fd,
            'family': socket.AddressFamily(conn.family).name, # AF_INET, AF_INET6
            'type': socket.SocketKind(conn.type).name,     # SOCK_STREAM, SOCK_DGRAM
            'laddr_ip': conn.laddr.ip if conn.laddr else 'N/A',
            'laddr_port': conn.laddr.port if conn.laddr else 'N/A',
            'raddr_ip': conn.raddr.ip if conn.raddr else 'N/A',
            'raddr_port': conn.raddr.port if conn.raddr else 'N/A',
            'status': conn.status,
            'pid': conn.pid,
            'process_name': 'N/A',
            'username': 'N/A',
            'identified_protocol': 'Unknown', # Default
            'bytes_sent_approx': 'N/A', # New field
            'bytes_received_approx': 'N/A' # New field
        }

        if conn.type == socket.SOCK_STREAM: # TCP
            traffic_stats['tcp_connections'] += 1
            # Attempt protocol identification for ESTABLISHED TCP connections on specific ports
            if conn.status == psutil.CONN_ESTABLISHED:
                target_ip_for_check = conn_detail['raddr_ip']
                target_port_for_check = conn_detail['raddr_port']
                
                # Check if either local or remote port matches our target ports
                # This logic assumes we're interested if *either end* of the connection is on a common service port.
                # For client-side checks, raddr_port is usually the service port.
                # For server-side checks (if this host is the server), laddr_port is the service port.

                # Port 443 (TLS/SSL)
                if target_port_for_check == 443 or conn_detail['laddr_port'] == 443:
                    # If laddr is 443, then raddr is the client. We can't probe the client with this logic easily.
                    # So, primarily focus on when raddr_port is 443 (outbound connection to a server on 443)
                    # or when laddr_port is 443 and raddr is a client we might want to get cert from (less common for this check)
                    # For simplicity, we'll check the remote end if its port is 443.
                    if target_port_for_check == 443:
                        try:
                            context = ssl.create_default_context()
                            # server_hostname should be the actual hostname the client intended to connect to,
                            # which might not be raddr_ip if it's a shared hosting IP.
                            # Using raddr_ip for SNI is a best guess here without more context.
                            with socket.create_connection((target_ip_for_check, target_port_for_check), timeout=1.0) as temp_sock:
                                with context.wrap_socket(temp_sock, server_hostname=target_ip_for_check) as ssock:
                                    # Successful handshake implies TLS/SSL
                                    conn_detail['identified_protocol'] = 'TLS/SSL'
                        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e_ssl:
                            # print(f"Debug: SSL/TLS check for {target_ip_for_check}:443 failed: {e_ssl}")
                            conn_detail['identified_protocol'] = 'TCP/443 (No TLS/SSL Handshake)'
                        except Exception: # Catch any other unexpected error
                            conn_detail['identified_protocol'] = 'TCP/443 (Check Error)'
                
                # Port 80 (HTTP)
                elif target_port_for_check == 80 or conn_detail['laddr_port'] == 80:
                    if target_port_for_check == 80: # Check remote server
                        try:
                            http_conn = http.client.HTTPConnection(target_ip_for_check, target_port_for_check, timeout=1)
                            http_conn.request('HEAD', '/')
                            http_conn.getresponse().close() # Just need to see if we get any valid HTTP response
                            conn_detail['identified_protocol'] = 'HTTP'
                            http_conn.close()
                        except (http.client.HTTPException, socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e_http:
                            # print(f"Debug: HTTP check for {target_ip_for_check}:80 failed: {e_http}")
                            conn_detail['identified_protocol'] = 'TCP/80 (No HTTP Response)'
                        except Exception:
                             conn_detail['identified_protocol'] = 'TCP/80 (Check Error)'

                # Port 22 (SSH)
                elif target_port_for_check == 22 or conn_detail['laddr_port'] == 22:
                    if target_port_for_check == 22: # Check remote server
                        ssh_sock = None
                        try:
                            ssh_sock = socket.create_connection((target_ip_for_check, target_port_for_check), timeout=1.0)
                            ssh_sock.settimeout(1.0)
                            banner = ssh_sock.recv(1024)
                            if banner.startswith(b'SSH-'):
                                conn_detail['identified_protocol'] = 'SSH'
                            else:
                                conn_detail['identified_protocol'] = 'TCP/22 (Unknown Banner)'
                        except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e_ssh:
                            # print(f"Debug: SSH check for {target_ip_for_check}:22 failed: {e_ssh}")
                            conn_detail['identified_protocol'] = 'TCP/22 (No SSH Banner)'
                        except Exception:
                            conn_detail['identified_protocol'] = 'TCP/22 (Check Error)'
                        finally:
                            if ssh_sock:
                                ssh_sock.close()
                                
        elif conn.type == socket.SOCK_DGRAM: # UDP
            traffic_stats['udp_connections'] += 1

        if conn.pid:
            try:
                process = psutil.Process(conn.pid)
                conn_detail['process_name'] = process.name()
                conn_detail['username'] = process.username()
            except psutil.NoSuchProcess:
                conn_detail['process_name'] = "(No Such Process)"
            except psutil.AccessDenied:
                conn_detail['process_name'] = "(Access Denied)"
            except Exception as e:
                conn_detail['process_name'] = f"(Error: {str(e)[:30]})" # Truncate error

        traffic_stats['connection_details'].append(conn_detail)

        # Generate finding for active connections
        if conn_detail['raddr_ip'] != 'N/A' and conn_detail['raddr_port'] != 'N/A': # Ensure raddr is populated
            # Finding generation moved after ss data processing
            pass # End of psutil loop for individual connection processing before ss data


    traffic_stats['active_connections_count'] = active_connections_count
    
    # --- Linux-Specific Traffic Volume Collection (using ss -ti) ---
    if platform.system() == "Linux":
        print(f"{COLOR_GREEN}[*] Attempting to gather TCP traffic volume using 'ss -ti'...{COLOR_RESET}")
        ss_traffic_data = {}
        # Regex to capture local/remote IP:Port
        # Handles IPv4: e.g., 192.168.1.10:44382
        # Handles IPv6: e.g., [::1]:44382 or [0:0:0:0:0:0:0:1]:44382
        # Also handles wildcard for port: [::1]:*
        ip_port_regex_str = r"((?:\[[0-9a-fA-F:]+\]|[\d\.]+):(?:[\d]+|\*))"
        
        # Regex for byte counts from the detailed line (often starts with whitespace)
        # Example: "     bytes_acked:1234 bytes_received:5678 ..."
        # Sometimes, other fields like 'mss', 'cwnd' can be between them.
        # Using non-greedy match for content between acked and received.
        bytes_regex = re.compile(r"bytes_acked:(\d+).*?bytes_received:(\d+)")
        
        ss_command = ["ss", "-tni"] # -t for tcp, -n for numeric, -i for internal TCP info
        success, ss_output = run_command(ss_command, timeout=10)

        if not success or not ss_output:
            add_finding_func(managed_findings, SEVERITY_LOW, "Traffic Volume Analysis Skipped",
                             f"Command '{' '.join(ss_command)}' failed or returned no output.",
                             "Ensure 'ss' utility is available and executable.")
            traffic_stats['errors'].append(f"ss command failed: {ss_output if not success else 'No output'}")
        else:
            current_connection_ss_info = {}
            lines = ss_output.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i]
                if line.strip().startswith("ESTAB"):
                    # Extract local and remote addresses from the ESTAB line
                    # Example: ESTAB 0 0 192.168.1.10:12345 1.2.3.4:https
                    #          or    ESTAB 0 0 [::1]:12345  [::1]:https
                    match_addrs = re.search(f"ESTAB.*?{ip_port_regex_str}\\s+{ip_port_regex_str}", line)
                    if match_addrs:
                        local_ip_port_str = match_addrs.group(1)
                        remote_ip_port_str = match_addrs.group(2)
                        
                        # Look for byte counts in the next line (usually)
                        if i + 1 < len(lines):
                            detail_line = lines[i+1]
                            bytes_match = bytes_regex.search(detail_line)
                            if bytes_match:
                                bytes_acked = int(bytes_match.group(1))
                                bytes_received = int(bytes_match.group(2))
                                
                                # Parse IP and Port from strings
                                try:
                                    l_ip, l_port_str = local_ip_port_str.rsplit(':', 1)
                                    r_ip, r_port_str = remote_ip_port_str.rsplit(':', 1)
                                    l_ip = l_ip.strip("[]") # For IPv6
                                    r_ip = r_ip.strip("[]") # For IPv6
                                    # Port can be '*' if it's a listener that hasn't fully established or specific cases
                                    # For established connections, psutil gives specific ports, so we expect numeric here from ss
                                    l_port = int(l_port_str) if l_port_str != '*' else 0 # Use 0 for wildcard, though psutil should have specific
                                    r_port = int(r_port_str) if r_port_str != '*' else 0
                                    
                                    key = ( (l_ip, l_port), (r_ip, r_port) )
                                    ss_traffic_data[key] = {'sent': bytes_acked, 'received': bytes_received}
                                except ValueError:
                                    pass # Malformed IP/Port string from ss output
                        i += 1 # Move past the detail line whether parsed or not
                i += 1

            # Correlate ss data with psutil connection details
            for detail in traffic_stats['connection_details']:
                if detail['type'] == 'SOCK_STREAM' and detail['status'] == psutil.CONN_ESTABLISHED:
                    # Ensure ports are integers for key matching
                    laddr_port_int = int(detail['laddr_port']) if isinstance(detail['laddr_port'], str) and detail['laddr_port'].isdigit() else detail['laddr_port']
                    raddr_port_int = int(detail['raddr_port']) if isinstance(detail['raddr_port'], str) and detail['raddr_port'].isdigit() else detail['raddr_port']

                    key = ( (detail['laddr_ip'], laddr_port_int), (detail['raddr_ip'], raddr_port_int) )
                    if key in ss_traffic_data:
                        detail['bytes_sent_approx'] = ss_traffic_data[key]['sent']
                        detail['bytes_received_approx'] = ss_traffic_data[key]['received']
    else:
        if any(cd['type'] == 'SOCK_STREAM' and cd['status'] == psutil.CONN_ESTABLISHED for cd in traffic_stats['connection_details']):
            add_finding_func(managed_findings, SEVERITY_INFO, "Traffic Volume Analysis Note",
                             "Traffic volume analysis via 'ss -ti' is currently only supported on Linux.",
                             "On other platforms, byte counts will show 'N/A'.")

    # Now generate findings for active connections, potentially with volume data
    for conn_detail in traffic_stats['connection_details']:
        if conn_detail['raddr_ip'] != 'N/A' and conn_detail['raddr_port'] != 'N/A':
            finding_title = "Active Connection Detected"
            protocol_info = f", Protocol: {conn_detail['identified_protocol']}" if conn_detail['identified_protocol'] != 'Unknown' else ""
            volume_info = ""
            if conn_detail['bytes_sent_approx'] != 'N/A' and conn_detail['bytes_received_approx'] != 'N/A':
                volume_info = f", Sent: {conn_detail['bytes_sent_approx']}B, Rcvd: {conn_detail['bytes_received_approx']}B"
            
            finding_desc = (
                f"Process: '{conn_detail['process_name']}' (PID: {conn_detail['pid'] or 'N/A'}, User: {conn_detail['username'] or 'N/A'}) "
                f"has an active connection: {conn_detail['laddr_ip']}:{conn_detail['laddr_port']} "
                f"-> {conn_detail['raddr_ip']}:{conn_detail['raddr_port']} "
                f"(Family: {conn_detail['family']}, Type: {conn_detail['type']}, Status: {conn_detail['status']}{protocol_info}{volume_info})"
            )
            add_finding_func(managed_findings, SEVERITY_INFO, finding_title, finding_desc,
                             "Review active connections for unexpected or unauthorized communications.")


    if not connections and active_connections_count == 0 : # Check if psutil returned no connections
        add_finding_func(managed_findings, SEVERITY_INFO, "No Active Network Connections", 
                         "No active (established or specific state) network connections were found by psutil at this time.",
                         "This is normal if the system has no active network communications during the scan.")

    managed_stats['local_traffic'] = traffic_stats
    print(f"{COLOR_GREEN}[+] Local network traffic analysis completed. Found {active_connections_count} active connections.{COLOR_RESET}")

if __name__ == '__main__':
    # Example Usage (requires a mock environment for managed_stats, managed_findings, add_finding_func)
    print("This module is intended to be run as part of the Guardian scanner.")
    
    # Mock objects for standalone testing (simplified)
    class MockManagerList:
        def __init__(self):
            self._list = []
        def append(self, item):
            self._list.append(item)
        def __repr__(self):
            return repr(self._list)

    mock_findings = {
        SEVERITY_INFO: MockManagerList(),
        SEVERITY_MEDIUM: MockManagerList(),
        SEVERITY_HIGH: MockManagerList(),
        SEVERITY_LOW: MockManagerList() # Added for new findings
    }
    mock_stats = {}

    def mock_add_finding(findings_dict, severity, title, description, recommendation="N/A"):
        print(f"[{severity}] {title}: {description} (Rec: {recommendation})")
        if severity in findings_dict:
            findings_dict[severity].append({'title': title, 'description': description, 'recommendation': recommendation})
        else:
            print(f"Error: Severity key {severity} not in mock_findings")

    print("\n--- Running Mock Analysis ---")
    try:
        analyze_local_traffic(mock_stats, mock_findings, mock_add_finding)
    except Exception as e:
        print(f"Error during mock analysis: {e}")
    
    print("\n--- Mock Stats ---")
    for key, value in mock_stats.get('local_traffic', {}).items():
        if key == 'connection_details' and isinstance(value, list):
            print(f"  {key}: [{len(value)} entries]")
            #for i, detail in enumerate(value[:2]): # Print first 2 details
            #    print(f"    Entry {i+1}: {detail}")
        else:
            print(f"  {key}: {value}")

    print("\n--- Mock Findings ---")
    for severity, findings_list in mock_findings.items():
        if findings_list._list: # Access internal list of MockManagerList
            print(f"  {severity.upper()}:") # Changed to severity.upper() for consistency
            for finding in findings_list._list[:2]: # Print first 2 findings of this severity
                print(f"    - {finding['title']}")
    
    print("\nNote: Standalone test provides limited insight. Full functionality within Guardian.")
    print("      Traffic volume (ss -ti) part of the test will only work on Linux and if 'ss' is runnable.")
