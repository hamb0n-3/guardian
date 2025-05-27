#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Running Process Analysis (including I/O counters)
"""

import psutil
import re
import socket # Already present from previous task, kept for protocol analysis
from datetime import datetime
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH
)

# Constants from previous task (protocol analysis) - kept for completeness of the module
COMMON_PORTS_TO_PROTOCOLS = {
    20: "FTP-Data", 21: "FTP-Control", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB/CIFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt" 
    # Simplified for brevity, full list was in previous state
}
PROCESS_NAME_TO_PROTOCOL_HINTS = {
    "sshd": "SSH", "nginx": "HTTP/HTTPS", "apache2": "HTTP/HTTPS", "httpd": "HTTP/HTTPS",
    "mysqld": "MySQL", "postgres": "PostgreSQL"
    # Simplified for brevity
}

# Helper function from previous task (protocol analysis) - kept for completeness
def _analyze_connections(process_info, connections, add_finding_func):
    analyzed_conns = []
    unknown_protocol_count = 0
    for conn in connections:
        conn_data = {
            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
            "status": conn.status,
            "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP" if conn.type == socket.SOCK_DGRAM else "Other",
            "identified_protocol": "Unknown",
            "protocol_certainty": "N/A"
        }
        lport = conn.laddr.port if conn.laddr else None
        rport = conn.raddr.port if conn.raddr else None
        proc_name = process_info.get('name', '').lower()

        if lport and lport in COMMON_PORTS_TO_PROTOCOLS:
            conn_data["identified_protocol"] = COMMON_PORTS_TO_PROTOCOLS[lport]
            conn_data["protocol_certainty"] = "Port-based (Local)"
        elif rport and rport in COMMON_PORTS_TO_PROTOCOLS and conn.status == psutil.CONN_ESTABLISHED:
            conn_data["identified_protocol"] = COMMON_PORTS_TO_PROTOCOLS[rport]
            conn_data["protocol_certainty"] = "Port-based (Remote, Established)"
        
        for name_hint, protocol_hint in PROCESS_NAME_TO_PROTOCOL_HINTS.items():
            if name_hint in proc_name:
                if conn_data["identified_protocol"] == "Unknown" or conn_data["protocol_certainty"].startswith("Port-based"):
                    if conn.status == psutil.CONN_LISTEN:
                        conn_data["identified_protocol"] = protocol_hint
                        conn_data["protocol_certainty"] = "Process-inferred (Listening)"
                    elif conn.status == psutil.CONN_ESTABLISHED and protocol_hint not in ["HTTP/HTTPS", "IMAP/POP3"]:
                        conn_data["identified_protocol"] = protocol_hint
                        conn_data["protocol_certainty"] = "Process-inferred (Established)"
                break
        if conn.status == psutil.CONN_ESTABLISHED and rport == 443:
            if conn_data["identified_protocol"] != "HTTPS":
                conn_data["identified_protocol"] = "HTTPS"
                conn_data["protocol_certainty"] = "Established to well-known remote port (443)"
        elif conn.status == psutil.CONN_ESTABLISHED and rport == 80:
             if conn_data["identified_protocol"] != "HTTP":
                conn_data["identified_protocol"] = "HTTP"
                conn_data["protocol_certainty"] = "Established to well-known remote port (80)"
        if conn_data["identified_protocol"] == "Unknown":
            conn_data["identified_protocol"] = f"Unknown {conn_data['type']}"
            conn_data["protocol_certainty"] = "Heuristic failed"
            unknown_protocol_count +=1
        if conn_data["protocol_certainty"].startswith("Port-based"):
            current_port_protocol = COMMON_PORTS_TO_PROTOCOLS.get(lport)
            if current_port_protocol:
                suspected_protocol_by_proc = None
                for name_h, proto_h in PROCESS_NAME_TO_PROTOCOL_HINTS.items():
                    if name_h in proc_name: suspected_protocol_by_proc = proto_h; break
                if suspected_protocol_by_proc and suspected_protocol_by_proc != current_port_protocol and not (current_port_protocol in suspected_protocol_by_proc or suspected_protocol_by_proc in current_port_protocol):
                     add_finding_func(managed_findings, SEVERITY_MEDIUM, f"Potential Protocol Mismatch on Port {lport} for PID {process_info.get('pid')}", f"Process '{proc_name}' (PID: {process_info.get('pid')}) is using port {lport} (typically {current_port_protocol}), but process name suggests it might be {suspected_protocol_by_proc}. Status: {conn.status}.", "Verify the process and its configuration.")
        analyzed_conns.append(conn_data)
    if unknown_protocol_count > 3 and unknown_protocol_count >= len(connections) / 2:
        add_finding_func(managed_findings, SEVERITY_LOW, f"Process with Multiple Unknown Protocols: {proc_name} (PID {process_info.get('pid')})", f"Process '{proc_name}' (PID: {process_info.get('pid')}) has {unknown_protocol_count} connections with undetermined protocols out of {len(connections)} total.", "Review this process's network activity.")
    return analyzed_conns

def get_running_processes(managed_stats, managed_findings, add_finding_func):
    """Gathers running process info, including I/O counters, network connections and identified protocols."""
    print(f"{COLOR_GREEN}[*] Gathering Running Process Information (including I/O and network details)...{COLOR_RESET}")
    processes_list_local = [] 
    process_count = 0
    process_stats_local = {'list': [], 'count': 0, 'error': None}

    HIGH_TRAFFIC_THRESHOLD_BYTES = 100 * 1024 * 1024  # 100MB

    try:
        attrs = ['pid', 'name', 'username', 'cmdline', 'create_time', 'status', 'ppid', 'cwd']
        for proc in psutil.process_iter(attrs=attrs, ad_value=None):
            process_count += 1
            proc_info_dict = proc.info # Use proc_info_dict consistently
            cmdline_str = ' '.join(proc_info_dict['cmdline']) if proc_info_dict['cmdline'] else '(N/A)'
            
            process_data = {
                "pid": proc_info_dict['pid'], "ppid": proc_info_dict['ppid'], "name": proc_info_dict['name'],
                "username": proc_info_dict['username'], "status": proc_info_dict['status'],
                "create_time": datetime.fromtimestamp(proc_info_dict['create_time']).isoformat() if proc_info_dict['create_time'] else 'N/A',
                "cmdline": cmdline_str, "cwd": proc_info_dict['cwd'],
                "bytes_sent": "N/A", # Initialize I/O fields
                "bytes_read": "N/A",
                "io_counters_error": None,
                "network_connections": [], # Initialize from previous task
                "network_connections_error": None # Initialize from previous task
            }
            
            # Get I/O counters
            try:
                io_counters = proc.io_counters()
                process_data["bytes_sent"] = io_counters.write_bytes # write_bytes for sent
                process_data["bytes_read"] = io_counters.read_bytes   # read_bytes for received
                
                if (isinstance(process_data["bytes_sent"], int) and process_data["bytes_sent"] > HIGH_TRAFFIC_THRESHOLD_BYTES) or \
                   (isinstance(process_data["bytes_read"], int) and process_data["bytes_read"] > HIGH_TRAFFIC_THRESHOLD_BYTES):
                    add_finding_func(
                        managed_findings, SEVERITY_MEDIUM,
                        f"High I/O Volume for Process: {proc_info_dict['name']}",
                        f"PID: {proc_info_dict['pid']}, Name: {proc_info_dict['name']}, User: {proc_info_dict['username']} "
                        f"has written {process_data['bytes_sent']:,} bytes and read {process_data['bytes_read']:,} bytes (total I/O).",
                        "Review this process's activity. High I/O can indicate heavy network use (data exfiltration, P2P, busy server) or intensive disk operations. Correlate with network connections for network-specific concerns."
                    )
            except psutil.AccessDenied:
                process_data["io_counters_error"] = "Access Denied"
                process_data["bytes_sent"] = -1 # Use -1 for unretrievable numeric data
                process_data["bytes_read"] = -1
            except psutil.NoSuchProcess:
                process_data["io_counters_error"] = "No Such Process (terminated while getting I/O)"
                process_data["bytes_sent"] = -1
                process_data["bytes_read"] = -1
            except Exception as e_io:
                process_data["io_counters_error"] = f"Error: {type(e_io).__name__}"
                process_data["bytes_sent"] = -1
                process_data["bytes_read"] = -1

            # Get and analyze network connections (from previous task)
            try:
                connections = proc.connections(kind='inet')
                if connections:
                    analyzed_conns = _analyze_connections(
                        {"pid": proc_info_dict['pid'], "name": proc_info_dict['name']}, 
                        connections, 
                        add_finding_func
                    )
                    process_data["network_connections"] = analyzed_conns
            except psutil.AccessDenied:
                process_data["network_connections_error"] = "Access Denied"
            except psutil.NoSuchProcess:
                process_data["network_connections_error"] = "No Such Process (terminated while getting connections)"
            except Exception as e_conn: 
                process_data["network_connections_error"] = f"Error getting connections: {type(e_conn).__name__}"

            # --- Basic Process Analysis (Existing) ---
            expected_root_procs = {
                'systemd', 'kthreadd', 'kernel_task', '[kthreadd]', 'NetworkManager', 'sshd',
                'rsyslogd', 'cron', 'dbus-daemon', 'login', 'agetty', 'auditd', 'polkitd',
                'udevd', 'containerd', 'dockerd', 'journald'
            }
            if proc_info['username'] == 'root' and proc_info['name'] not in expected_root_procs:
                add_finding_func(
                    managed_findings, SEVERITY_LOW,
                    f"Process Running as Root: {proc_info['name']}",
                    f"PID: {proc_info['pid']}, Cmd: {cmdline_str}. Verify necessity.",
                    "Configure to run as less privileged user if possible."
                )

            suspicious_paths = ['/tmp', '/var/tmp', '/dev/shm']
            if proc_info['cwd'] and any(proc_info['cwd'].startswith(path) for path in suspicious_paths):
                 add_finding_func(
                     managed_findings, SEVERITY_MEDIUM,
                     f"Process Running from Suspicious Location: {proc_info['name']}",
                     f"PID: {proc_info['pid']}, CWD: {proc_info['cwd']}, User: {proc_info['username']}.",
                     "Investigate process origin. Could indicate malware/misconfiguration."
                 )

            if re.search(r'nc -l[vp]', cmdline_str) or re.search(r'ncat -l[vp]', cmdline_str):
                 add_finding_func(managed_findings, SEVERITY_HIGH, "Potential Listener Detected (nc/ncat)", f"PID: {proc_info['pid']}, Cmd: {cmdline_str}.", "Verify legitimacy. Unauthorized listeners can be backdoors.")
            if re.search(r'python .* SimpleHTTPServer', cmdline_str, re.IGNORECASE) or re.search(r'python -m http.server', cmdline_str):
                 add_finding_func(managed_findings, SEVERITY_MEDIUM, "Python HTTP Server Detected", f"PID: {proc_info['pid']}, Cmd: {cmdline_str}.", "Verify intent. Simple servers lack security, may expose data.")

    except psutil.AccessDenied:
        warning_msg = "Access denied retrieving some process details. Run as root for full info."
        print(f"{COLOR_YELLOW}Warning: {warning_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_LOW, "Process Scan Permissions Issue", warning_msg)
        process_stats_local['error'] = warning_msg
    except Exception as e:
        error_msg = f"Failed to gather process info: {e}"
        print(f"{COLOR_RED}Error gathering running processes: {e}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Process Info Error", error_msg)
        process_stats_local['error'] = error_msg

    # Update managed stats
    process_stats_local['list'] = processes_list_local
    process_stats_local['count'] = process_count
    managed_stats['processes'] = process_stats_local 