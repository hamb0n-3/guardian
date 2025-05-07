#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Running Process Analysis
"""

import psutil
import re
from datetime import datetime
# Remove direct import of add_finding
# from guardian import add_finding
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH
)

def get_running_processes(managed_stats, managed_findings, add_finding_func):
    """Gathers running process info, storing results in managed dicts."""
    print(f"{COLOR_GREEN}[*] Gathering Running Process Information...{COLOR_RESET}")
    processes_list_local = [] # Store process data locally first
    process_count = 0
    process_stats_local = {} # Store stats locally

    try:
        attrs = ['pid', 'name', 'username', 'cmdline', 'create_time', 'status', 'ppid', 'cwd']
        for proc in psutil.process_iter(attrs=attrs, ad_value=None):
            process_count += 1
            proc_info = proc.info
            cmdline_str = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '(N/A)'
            process_data = {
                "pid": proc_info['pid'], "ppid": proc_info['ppid'], "name": proc_info['name'],
                "username": proc_info['username'], "status": proc_info['status'],
                "create_time": datetime.fromtimestamp(proc_info['create_time']).isoformat() if proc_info['create_time'] else 'N/A',
                "cmdline": cmdline_str, "cwd": proc_info['cwd']
            }
            processes_list_local.append(process_data)

            # --- Basic Analysis ---
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