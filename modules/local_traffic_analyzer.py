#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Local Network Traffic Analyzer
"""

import psutil
import socket
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_HIGH, SEVERITY_MEDIUM
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
            'username': 'N/A'
        }

        if conn.type == socket.SOCK_STREAM: # TCP
            traffic_stats['tcp_connections'] += 1
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
            finding_title = "Active Connection Detected"
            finding_desc = (
                f"Process: '{conn_detail['process_name']}' (PID: {conn_detail['pid'] or 'N/A'}, User: {conn_detail['username'] or 'N/A'}) "
                f"has an active connection: {conn_detail['laddr_ip']}:{conn_detail['laddr_port']} "
                f"-> {conn_detail['raddr_ip']}:{conn_detail['raddr_port']} "
                f"(Family: {conn_detail['family']}, Type: {conn_detail['type']}, Status: {conn_detail['status']})"
            )
            add_finding_func(managed_findings, SEVERITY_INFO, finding_title, finding_desc, 
                             "Review active connections for unexpected or unauthorized communications.")

    traffic_stats['active_connections_count'] = active_connections_count
    
    if not connections:
        add_finding_func(managed_findings, SEVERITY_INFO, "No Active Network Connections", 
                         "No active (established or specific state) network connections were found at this time.",
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
        SEVERITY_HIGH: MockManagerList()
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
            print(f"  {severity}:")
            for finding in findings_list._list[:2]: # Print first 2 findings of this severity
                print(f"    - {finding['title']}")
    
    print("\nNote: Standalone test provides limited insight. Full functionality within Guardian.")
