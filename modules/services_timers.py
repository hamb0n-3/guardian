#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Systemd Services and Timers Analysis

Checks systemd units for potential misconfigurations or risks.
"""

import re
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
    run_command
)

# --- Systemd Analysis Functions ---

def check_systemd_units(managed_stats, managed_findings, add_finding_func):
    """Analyzes systemd running services and active timers."""
    print(f"\n{COLOR_GREEN}[*] Analyzing Systemd Services and Timers...{COLOR_RESET}")
    service_stats_local = {
        'running_services': [],
        'active_timers': [],
        'user_units_checked': False,
        'error': None
    }
    running_services_list = []
    active_timers_list = []

    # --- Check Running System Services ---
    try:
        cmd_services = ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--plain', '--no-legend']
        services_output = run_command(cmd_services)
        if services_output:
            for line in services_output.strip().split('\n'):
                parts = line.split(None, 4) # UNIT, LOAD, ACTIVE, SUB, DESCRIPTION
                if len(parts) >= 5:
                    unit_name = parts[0]
                    description = parts[4]
                    service_info = {'unit': unit_name, 'description': description, 'path': None}
                    
                    # Try to get the unit file path
                    try:
                        cmd_path = ['systemctl', 'show', '--property=FragmentPath', unit_name]
                        path_output = run_command(cmd_path)
                        if path_output and '=' in path_output:
                            service_info['path'] = path_output.split('=', 1)[1].strip()
                    except Exception:
                        pass # Ignore errors getting path for individual units

                    running_services_list.append(service_info)

                    # Basic Analysis:
                    # 1. Check for services running from suspicious paths
                    suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/home/']
                    if service_info['path'] and any(service_info['path'].startswith(p) for p in suspicious_paths):
                        add_finding_func(managed_findings, SEVERITY_HIGH, "Service Running from Suspicious Location", 
                                         f"Service '{unit_name}' unit file is located in a non-standard/suspicious path: {service_info['path']}",
                                         "Investigate this service immediately. It could indicate malware persistence.")

                    # 2. Flag known risky services (can refine this list)
                    risky_services = {'telnet.socket', 'telnetd.service', 'vsftpd.service', 'proftpd.service'}
                    if unit_name in risky_services:
                         add_finding_func(managed_findings, SEVERITY_HIGH, f"Potentially Risky Service Running: {unit_name}",
                                          f"Service '{unit_name}' ({description}) is running.",
                                          "Verify if this service is necessary and securely configured. Consider disabling if not needed.")
                         
        else:
            print(f"{COLOR_YELLOW}Info: Could not get list of running systemd services.{COLOR_RESET}")
            if not service_stats_local['error']: service_stats_local['error'] = "Failed to list running services"

    except Exception as e:
        msg = f"Error checking systemd services: {e}"
        print(f"{COLOR_RED}Error: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_MEDIUM, "Systemd Service Check Error", msg)
        if not service_stats_local['error']: service_stats_local['error'] = msg

    service_stats_local['running_services'] = running_services_list

    # --- Check Active System Timers ---
    try:
        cmd_timers = ['systemctl', 'list-timers', '--no-pager', '--plain', '--no-legend']
        timers_output = run_command(cmd_timers)
        if timers_output:
            # Example Line: NEXT                        LEFT          LAST                        PASSED       UNIT                         ACTIVATES
            # Mon 2023-10-30 10:00:00 EDT 11h left      Sun 2023-10-29 10:00:00 EDT 12h ago      apt-daily.timer            apt-daily.service
            for line in timers_output.strip().split('\n'):
                parts = line.split(None, 5) # Split loosely based on columns
                if len(parts) >= 6:
                    unit = parts[-2] # UNIT is usually second to last
                    activates = parts[-1] # ACTIVATES is usually last
                    timer_info = {'unit': unit, 'activates': activates, 'schedule_info': line.strip()}
                    active_timers_list.append(timer_info)

                    # Basic Analysis:
                    # 1. Look for timers running very frequently (e.g., every minute/second) - might indicate persistence attempt or misconfiguration
                    # This regex is basic and might need refinement
                    if re.search(r'\d+\s+(sec|min)\s+left', line, re.IGNORECASE) or re.search(r'every\s+\d+\s+(sec|min)', line, re.IGNORECASE):
                         add_finding_func(managed_findings, SEVERITY_LOW, "Timer Running Very Frequently",
                                          f"Timer '{unit}' (activates: {activates}) appears to run every minute or less.",
                                          "Verify the purpose and necessity of this frequent timer.")
                        
        else:
            print(f"{COLOR_YELLOW}Info: Could not get list of active systemd timers.{COLOR_RESET}")
            if not service_stats_local['error']: service_stats_local['error'] = "Failed to list active timers"

    except Exception as e:
        msg = f"Error checking systemd timers: {e}"
        print(f"{COLOR_RED}Error: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_MEDIUM, "Systemd Timer Check Error", msg)
        if not service_stats_local['error']: service_stats_local['error'] = msg

    service_stats_local['active_timers'] = active_timers_list

    # TODO: Add checks for user services/timers (`systemctl --user ...`) - requires running as that user or specific privileges.

    managed_stats['services_timers'] = service_stats_local 