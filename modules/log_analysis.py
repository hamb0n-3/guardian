#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Log Analysis

Parses system logs for security-relevant events.
"""

import os
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta # For time-based analysis (optional)

from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
)

# --- Log Analysis Functions ---

def analyze_auth_log(managed_stats, managed_findings, add_finding_func, log_path="/var/log/auth.log"):
    """Analyzes authentication logs (e.g., /var/log/auth.log) for suspicious activity."""
    print(f"\n{COLOR_GREEN}[*] Analyzing Authentication Log ({log_path})...{COLOR_RESET}")
    log_stats_local = {
        'log_path': log_path,
        'exists': False,
        'readable': False,
        'lines_parsed': 0,
        'failed_logins': 0,
        'sudo_sessions': 0,
        'error': None
    }

    if not os.path.exists(log_path):
        msg = f"Log file not found: {log_path}"
        print(f"{COLOR_YELLOW}Info: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_LOW, "Log File Missing", msg, "Verify log configuration or path.")
        log_stats_local['error'] = msg
        managed_stats['log_analysis'] = log_stats_local # Store basic info
        return

    log_stats_local['exists'] = True

    # Limit lines read for performance? Maybe check file size first?
    # For now, read the whole file if readable.
    # TODO: Implement more robust log reading (handle rotation, large files)
    lines_to_check = 1000 # Limit initial check to last N lines for performance
    failed_login_attempts = defaultdict(list) # Store timestamps of failures per source/user

    try:
        # Read last N lines efficiently if possible (seek)
        # Basic approach: read all, then take last N
        with open(log_path, 'r') as f:
            log_stats_local['readable'] = True
            all_lines = f.readlines()
            lines = all_lines[-lines_to_check:] # Get the last N lines
            log_stats_local['lines_parsed'] = len(lines)

            for line in lines:
                # --- Failed Password/Auth --- (Regex needs refinement for different formats)
                fail_match = re.search(r'(?:Failed password|Authentication failure) for (invalid user )?(\S+)(?: from (\S+))?', line, re.IGNORECASE)
                if fail_match:
                    log_stats_local['failed_logins'] += 1
                    user = fail_match.group(2)
                    ip = fail_match.group(3) or 'Unknown IP'
                    source = f"{user}@{ip}"
                    # Simple finding for each failure (can be noisy)
                    add_finding_func(managed_findings, SEVERITY_MEDIUM, "Failed Login Attempt",
                                     f"User: {user}, Source IP: {ip}. Line: ...{line.strip()[-100:]}", # Show end of line
                                     "Monitor for brute-force attempts. Consider tools like fail2ban.")
                    # TODO: Add time-based correlation for brute-force detection
                    
                # --- Sudo Usage --- 
                sudo_match = re.search(r'sudo:.*:\s+(\S+)\s+:\s+USER=(\S+)\s+.*COMMAND=(.*)', line)
                if sudo_match:
                    log_stats_local['sudo_sessions'] += 1
                    user = sudo_match.group(1)
                    run_as = sudo_match.group(2)
                    command = sudo_match.group(3)
                    add_finding_func(managed_findings, SEVERITY_INFO, "Sudo Command Executed",
                                     f"User '{user}' ran command as '{run_as}': {command}",
                                     "Verify command legitimacy if user/command seems suspicious.")

                # --- SSH Logins (Successful) --- Might be INFO or LOW
                ssh_login_match = re.search(r'Accepted password|Accepted publickey for (\S+) from (\S+) port (\d+)', line)
                if ssh_login_match:
                     user = ssh_login_match.group(1)
                     ip = ssh_login_match.group(2)
                     port = ssh_login_match.group(3)
                     add_finding_func(managed_findings, SEVERITY_INFO, "Successful SSH Login",
                                      f"User '{user}' logged in from {ip}:{port}",
                                      "Monitor for unauthorized access.")

                # Add more patterns: user additions/deletions, service starts/stops, critical errors etc.

    except PermissionError:
        msg = f"Permission denied reading log file: {log_path}"
        print(f"{COLOR_RED}Error: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Log Read Error", msg, "Run script with sufficient privileges (e.g., root or log group membership)." )
        log_stats_local['error'] = msg
    except Exception as e:
        msg = f"Error analyzing log file {log_path}: {e}"
        print(f"{COLOR_RED}Error: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Log Analysis Error", msg)
        log_stats_local['error'] = msg
    
    # Store collected stats
    managed_stats['log_analysis'] = log_stats_local

# --- Add functions for other logs (syslog, journald) here ---
# Example placeholder for journald
def analyze_journald(managed_stats, managed_findings, add_finding_func):
    print(f"\n{COLOR_YELLOW}[*] Journald analysis not yet implemented.{COLOR_RESET}")
    # Use subprocess to run journalctl commands if library not available
    # e.g., journalctl -p err..alert , journalctl _COMM=sudo, journalctl _SYSTEMD_UNIT=sshd.service --since "1 hour ago"
    pass 