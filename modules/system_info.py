#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: System Information Gathering
"""

import platform
import socket
import psutil
from datetime import datetime

# Remove direct import of add_finding from guardian
# from guardian import add_finding
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
)

def get_system_info(managed_stats, managed_findings, add_finding_func):
    """
    Gathers basic OS and hardware info, storing results in managed dicts.

    Args:
        managed_stats (Manager.dict): Shared dict for statistics.
        managed_findings (Manager.dict): Shared dict for findings.
        add_finding_func (function): Function to add findings (e.g., add_finding_mp).
    """
    print(f"{COLOR_GREEN}[*] Gathering System Information...{COLOR_RESET}")
    # Store system stats under a key in the managed dict
    # Assigning a regular dict here is okay as this key is specific to this module/process
    system_stats_local = {}
    try:
        # Get OS information
        system_stats_local['os_name'] = platform.system()
        system_stats_local['os_version'] = platform.release()
        # platform.dist() is deprecated and removed in Python 3.8+
        # Use shutil.which('lsb_release') or parse /etc/os-release for a robust alternative
        # Basic fallback for now:
        try:
            with open("/etc/os-release") as f:
                os_release_info = dict(line.strip().split('=', 1) for line in f if '=' in line)
                distro = os_release_info.get('PRETTY_NAME', 'N/A').strip('"')
        except FileNotFoundError:
             # platform.linux_distribution() is also deprecated/removed
             # Consider using the 'distro' package if available: import distro; distro.name(pretty=True)
            distro = "N/A (requires /etc/os-release or 'distro' package)"
        system_stats_local['os_distro'] = distro
        system_stats_local['architecture'] = platform.machine()
        system_stats_local['hostname'] = socket.gethostname()
        system_stats_local['kernel_version'] = platform.uname().release

        # Use the passed function to add findings
        add_finding_func(
            managed_findings,
            SEVERITY_INFO,
            "Operating System Information",
            f"OS: {system_stats_local['os_name']} {system_stats_local['os_version']}, "
            f"Distro: {system_stats_local['os_distro']}, "
            f"Arch: {system_stats_local['architecture']}, "
            f"Kernel: {system_stats_local['kernel_version']}, "
            f"Hostname: {system_stats_local['hostname']}"
        )

        # Get CPU and Memory
        system_stats_local['cpu_count'] = psutil.cpu_count(logical=True)
        psutil.cpu_percent(interval=None)
        system_stats_local['cpu_percent'] = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        system_stats_local['memory_total_gb'] = round(mem.total / (1024**3), 2)
        system_stats_local['memory_used_percent'] = mem.percent

        add_finding_func(
            managed_findings,
            SEVERITY_INFO,
            "Resource Utilization",
            f"CPU Count: {system_stats_local['cpu_count']}, "
            f"CPU Usage: {system_stats_local['cpu_percent']}%, "
            f"Memory Total: {system_stats_local['memory_total_gb']} GB, "
            f"Memory Used: {system_stats_local['memory_used_percent']}%"
        )

        # Assign the collected local stats to the managed dictionary
        # This makes the data available to the main process after join()
        managed_stats['system'] = system_stats_local

    except Exception as e:
        print(f"{COLOR_RED}Error gathering basic system info: {e}{COLOR_RESET}")
        # Add error finding using the provided function
        add_finding_func(managed_findings, SEVERITY_HIGH, "System Info Error", f"Failed to gather basic system info: {e}")
        # Ensure the key exists even if there was an error, storing the error message
        if 'system' not in managed_stats:
             managed_stats['system'] = {}
        managed_stats['system']['error'] = str(e)