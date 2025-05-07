#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: SSH Configuration Analysis
"""

import os
import re # Needed for future checks if not currently used
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL
)

def check_ssh_config(managed_stats, managed_findings, add_finding_func, config_path="/etc/ssh/sshd_config"):
    """Analyzes SSHd config, storing results in managed dicts."""
    print(f"\n{COLOR_GREEN}[*] Analyzing SSH Configuration ({config_path})...{COLOR_RESET}")
    # Store results locally first
    ssh_stats_local = {'path': config_path, 'exists': False, 'directives': {}, 'error': None}
    config = {}

    if not os.path.exists(config_path):
        add_finding_func(managed_findings, SEVERITY_INFO, "SSH Server Configuration Not Found", f"SSHd config file not found at {config_path}.")
        print(f"{COLOR_YELLOW}Info: SSH configuration file {config_path} not found.{COLOR_RESET}")
        managed_stats['ssh_config'] = ssh_stats_local # Store basic info even if not found
        return

    ssh_stats_local['exists'] = True

    try:
        with open(config_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                parts = line.split(None, 1) # Split only on the first whitespace
                if len(parts) == 2:
                    key = parts[0]
                    value = parts[1]
                    # Store the last occurrence of the key, as sshd does
                    config[key] = value
                    # Also store in statistics for reference
                    ssh_stats_local['directives'][key] = value
                else:
                    # Handle lines that might not be key-value pairs
                    add_finding_func(managed_findings, SEVERITY_LOW, "Malformed Line in sshd_config", f"L{line_num} in {config_path}: '{line}'")

        # --- Analyze Directives ---
        # Protocol
        protocol = config.get('Protocol', '2')
        if protocol != '2':
            add_finding_func(managed_findings, SEVERITY_HIGH, "SSH Protocol 1 Enabled", f"'Protocol {protocol}' set.", "Ensure 'Protocol 2' is set.")
        else:
             add_finding_func(managed_findings, SEVERITY_INFO, "SSH Protocol", "Protocol 2 is correctly configured.")

        # PermitRootLogin
        permit_root_login = config.get('PermitRootLogin', 'prohibit-password')
        if permit_root_login.lower() == 'yes':
            add_finding_func(managed_findings, SEVERITY_HIGH, "SSH Root Login Permitted", "'PermitRootLogin yes' found.", "Set to 'no' or 'prohibit-password'.")
        elif permit_root_login.lower() in ['without-password', 'prohibit-password']:
             add_finding_func(managed_findings, SEVERITY_INFO, "SSH Root Login", f"Restricted ('{permit_root_login}').")
        elif permit_root_login.lower() == 'no':
             add_finding_func(managed_findings, SEVERITY_INFO, "SSH Root Login", "Disabled ('no').")
        else:
             add_finding_func(managed_findings, SEVERITY_INFO, "SSH Root Login", f"Set to '{permit_root_login}'. Verify policy.")

        # PasswordAuthentication
        password_auth = config.get('PasswordAuthentication', 'yes')
        if password_auth.lower() == 'yes':
            add_finding_func(managed_findings, SEVERITY_MEDIUM, "SSH Password Authentication Enabled", "Allows password logins.", "Disable ('PasswordAuthentication no') and use key-based auth.")
        else:
            add_finding_func(managed_findings, SEVERITY_INFO, "SSH Password Authentication", "Disabled ('no').")

        # PermitEmptyPasswords
        permit_empty_passwords = config.get('PermitEmptyPasswords', 'no')
        if permit_empty_passwords.lower() == 'yes':
            add_finding_func(managed_findings, SEVERITY_CRITICAL, "SSH Allows Empty Passwords", "Major security risk.", "Ensure 'PermitEmptyPasswords no' is set.")

        # UsePAM
        use_pam = config.get('UsePAM', 'yes')
        if use_pam.lower() == 'yes':
            add_finding_func(managed_findings, SEVERITY_INFO, "SSH PAM Integration", "Enabled.", "Ensure PAM is securely configured.")
        else:
             add_finding_func(managed_findings, SEVERITY_MEDIUM, "SSH PAM Integration Disabled", "'UsePAM no' bypasses PAM policies.", "Enable PAM ('UsePAM yes') unless specifically intended.")

        # X11Forwarding
        x11_forwarding = config.get('X11Forwarding', 'no')
        if x11_forwarding.lower() == 'yes':
            add_finding_func(managed_findings, SEVERITY_MEDIUM, "SSH X11 Forwarding Enabled", "Potential security risk.", "Disable ('X11Forwarding no') if not required.")
        else:
            add_finding_func(managed_findings, SEVERITY_INFO, "SSH X11 Forwarding", "Disabled.")

        # MaxAuthTries
        max_auth_tries = config.get('MaxAuthTries', '6')
        try:
            if int(max_auth_tries) > 4:
                add_finding_func(managed_findings, SEVERITY_LOW, "SSH Max Authentication Tries High", f"Value: {max_auth_tries}. Hinders brute-force slightly less.", "Set to 3 or 4.")
            else:
                 add_finding_func(managed_findings, SEVERITY_INFO, "SSH Max Authentication Tries", f"Reasonable value ({max_auth_tries}).")
        except ValueError:
             add_finding_func(managed_findings, SEVERITY_MEDIUM, "Invalid SSH MaxAuthTries Value", f"Value '{max_auth_tries}' not integer.", "Correct value in sshd_config.")

        # LoginGraceTime
        login_grace_time = config.get('LoginGraceTime', '120')
        try:
            grace_seconds = 0
            # Basic parsing for seconds/minutes
            if isinstance(login_grace_time, str):
                 if login_grace_time.endswith('m'): grace_seconds = int(login_grace_time[:-1]) * 60
                 elif login_grace_time.endswith('s'): grace_seconds = int(login_grace_time[:-1])
                 else: grace_seconds = int(login_grace_time) # Assume seconds
            else: grace_seconds = int(login_grace_time)

            if grace_seconds > 60:
                add_finding_func(managed_findings, SEVERITY_LOW, "SSH Login Grace Time Long", f"Value: {login_grace_time} ({grace_seconds}s).", "Set to shorter duration (e.g., 30 or 60).")
            else:
                 add_finding_func(managed_findings, SEVERITY_INFO, "SSH Login Grace Time", f"Reasonable duration ({login_grace_time}).")
        except ValueError:
             add_finding_func(managed_findings, SEVERITY_MEDIUM, "Invalid SSH LoginGraceTime Value", f"Value '{login_grace_time}' not valid time.", "Correct value (e.g., '30s', '60').")

        # ClientAliveInterval / ClientAliveCountMax
        client_alive_interval = config.get('ClientAliveInterval', '0')
        client_alive_count_max = config.get('ClientAliveCountMax', '3')
        try:
            interval = int(client_alive_interval)
            count = int(client_alive_count_max)
            if interval > 0 and count > 0:
                 total_timeout = interval * count
                 add_finding_func(managed_findings, SEVERITY_INFO, "SSH Client Keep-Alive Enabled", f"Interval={interval}s, CountMax={count}. Timeout ~{total_timeout}s.", "Ensure timeout meets policy.")
                 if total_timeout > 3600:
                     add_finding_func(managed_findings, SEVERITY_LOW, "SSH Client Keep-Alive Timeout Long", f"Timeout ({total_timeout}s) > 1 hour.", "Consider reducing interval/count.")
            else:
                 add_finding_func(managed_findings, SEVERITY_LOW, "SSH Client Keep-Alive Disabled", "Idle sessions won't timeout via SSHd.", "Consider enabling (e.g., 'ClientAliveInterval 300').")
        except ValueError:
             add_finding_func(managed_findings, SEVERITY_MEDIUM, "Invalid SSH ClientAlive Value(s)", f"Interval ('{client_alive_interval}') or CountMax ('{client_alive_count_max}') invalid.", "Correct values in sshd_config.")

        # AllowUsers / AllowGroups / DenyUsers / DenyGroups
        access_control_directives = ['AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups']
        for directive in access_control_directives:
            if directive in config:
                level = SEVERITY_INFO
                type_str = "Restricted" if "Allow" in directive else "Denied"
                by_type = "User" if "Users" in directive else "Group"
                add_finding_func(managed_findings, level, f"SSH Access {type_str} by {by_type}", f"'{directive}' directive is used: {config[directive]}. Access policies are applied.")

        # LogLevel
        log_level = config.get('LogLevel', 'INFO')
        if log_level.upper() not in ['INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3']:
             add_finding_func(managed_findings, SEVERITY_LOW, "SSH LogLevel Potentially Insufficient", f"Level: {log_level}. May lack detail.", "Consider 'INFO' or 'VERBOSE'.")
        elif log_level.upper() in ['DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3']:
             add_finding_func(managed_findings, SEVERITY_INFO, "SSH LogLevel Verbose", f"LogLevel is set to '{log_level}', providing detailed logs (may be noisy). Check log rotation.")
        else: # INFO or VERBOSE
            add_finding_func(managed_findings, SEVERITY_INFO, "SSH LogLevel", f"LogLevel is set to '{log_level}'.")

        # Add checks for Ciphers, MACs, KexAlgorithms, Banner, UseDNS etc.

    except FileNotFoundError:
        pass # Handled above
    except PermissionError:
        error_msg = f"Permission denied reading {config_path}. Run as root."
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "SSH Config Read Error", error_msg, "Run as root.")
        ssh_stats_local['error'] = 'Permission denied'
    except Exception as e:
        error_msg = f"Error analyzing SSH configuration: {e}"
        print(f"{COLOR_RED}{error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "SSH Config Analysis Error", f"Error analyzing {config_path}: {e}")
        ssh_stats_local['error'] = str(e)
    
    # Update managed stats at the end
    managed_stats['ssh_config'] = ssh_stats_local 