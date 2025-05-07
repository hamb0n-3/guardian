#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: User Account and Privilege Analysis
"""

import os
import re
# Remove direct import of add_finding
# from guardian import add_finding
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    run_command # Keep if needed for visudo checks later
)

def check_user_accounts(managed_stats, managed_findings, add_finding_func):
    """Analyzes user accounts/privileges, storing results in managed dicts."""
    print(f"\n{COLOR_GREEN}[*] Analyzing User Accounts and Privileges...{COLOR_RESET}")
    # Store results locally before assigning to managed dict
    user_stats_local = {
        'passwd_path': '/etc/passwd',
        'shadow_path': '/etc/shadow',
        'sudoers_path': '/etc/sudoers',
        'accounts': [],
        'sudo_rules': [],
        'error': None
    }
    accounts_list = [] # Build lists locally
    sudo_rules_list = []

    # --- /etc/passwd Analysis ---
    passwd_file = user_stats_local['passwd_path']
    try:
        with open(passwd_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'): continue
                fields = line.split(':')
                if len(fields) != 7:
                    add_finding_func(managed_findings, SEVERITY_LOW, "Malformed Line in /etc/passwd", f"L{line_num}: '{line}'")
                    continue
                username, _, uid_str, gid_str, _, home_dir, shell = fields
                account_info = {'username': username, 'uid': -1, 'gid': -1, 'home_dir': home_dir, 'shell': shell, 'passwd_line': line_num}
                try:
                    uid = int(uid_str)
                    gid = int(gid_str)
                    account_info['uid'] = uid
                    account_info['gid'] = gid
                    # Use add_finding_func
                    if uid == 0 and username != 'root':
                        add_finding_func(managed_findings, SEVERITY_CRITICAL, f"Non-Root Account with UID 0: {username}", f"Account has UID 0. L{line_num}", "Investigate immediately. Change UID if not intentional.")
                    elif uid == 0 and username == 'root':
                        add_finding_func(managed_findings, SEVERITY_INFO, "Root Account Found", "Standard root account (UID 0) exists.", "Ensure strong password and disabled direct SSH login.")
                    valid_shells = {'/bin/bash', '/bin/sh', '/bin/zsh', '/bin/ksh', '/bin/csh', '/bin/tcsh', '/usr/bin/bash', '/usr/bin/sh', '/usr/bin/zsh'}
                    no_login_shells = {'/sbin/nologin', '/usr/sbin/nologin', '/bin/false'}
                    if shell not in valid_shells and shell not in no_login_shells:
                         add_finding_func(managed_findings, SEVERITY_LOW, f"Account with Non-Standard Shell: {username}", f"UID: {uid}, Shell: '{shell}'. L{line_num}", "Verify shell is intended/secure. Use /sbin/nologin for service accounts.")
                    elif shell in no_login_shells:
                        add_finding_func(managed_findings, SEVERITY_INFO, f"Account with No Login Shell: {username}", f"UID: {uid}, Shell: '{shell}'. Likely cannot log in interactively.")
                    common_users = {'admin', 'test', 'guest', 'user', 'backup', 'administrator', 'support'}
                    if username.lower() in common_users and username != 'root':
                        add_finding_func(managed_findings, SEVERITY_LOW, f"Potentially Guessable Username: {username}", f"L{line_num}", "Consider less predictable usernames.")
                    if home_dir and not os.path.isdir(home_dir) and shell not in no_login_shells:
                        add_finding_func(managed_findings, SEVERITY_LOW, f"Home Directory Missing: {username}", f"Home '{home_dir}' missing. L{line_num}")
                    accounts_list.append(account_info)
                except ValueError:
                    add_finding_func(managed_findings, SEVERITY_MEDIUM, "Invalid UID/GID in /etc/passwd", f"L{line_num}: UID '{uid_str}' or GID '{gid_str}'.")
    except FileNotFoundError:
        msg = f"{passwd_file} not found."
        print(f"{COLOR_RED}Error: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_CRITICAL, "Password File Missing", msg)
        user_stats_local['error'] = msg
    except PermissionError:
        msg = f"Permission denied reading {passwd_file}."
        print(f"{COLOR_RED}Error: {msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Password File Read Error", msg + " Basic user info unavailable.")
        user_stats_local['error'] = msg
    except Exception as e:
        msg = f"Error analyzing {passwd_file}: {e}"
        print(f"{COLOR_RED}Error reading {passwd_file}: {e}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "Password File Analysis Error", msg)
        user_stats_local['error'] = msg
    # Store collected list in local stats dict
    user_stats_local['accounts'] = accounts_list

    # --- /etc/shadow Analysis ---
    shadow_file = user_stats_local['shadow_path']
    if os.geteuid() == 0:
        if os.path.exists(shadow_file):
            try:
                with open(shadow_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith('#'): continue
                        fields = line.split(':')
                        if len(fields) < 2:
                            add_finding_func(managed_findings, SEVERITY_LOW, "Malformed Line in /etc/shadow", f"L{line_num}: '{line}'")
                            continue
                        username, password_hash = fields[0], fields[1]
                        # Use add_finding_func
                        if not password_hash:
                            add_finding_func(managed_findings, SEVERITY_CRITICAL, f"Account with Empty Password Hash: {username}", f"Empty hash in {shadow_file}. L{line_num}", "Lock account ('passwd -l ...') or set password.")
                        elif password_hash in ['!', '*' ,'*LK*', '!!']:
                            add_finding_func(managed_findings, SEVERITY_INFO, f"Account Potentially Locked/Disabled: {username}", f"Indicator '{password_hash}' in {shadow_file}. L{line_num}")
                        if len(fields) >= 5: # Check if max_days field exists
                           max_days = fields[4] # Corrected index for Maximum Password Age
                           # Check for values indicating no expiration (99999, empty, or -1)
                           if max_days == '99999' or max_days == '' or max_days == '-1':
                               add_finding_func(managed_findings, SEVERITY_LOW, f"Password Never Expires: {username}", f"Max days: {max_days if max_days else '(none)'}. L{line_num}", "Implement password expiration policy (e.g., 90 days).")
            except PermissionError:
                msg = f"Could not read {shadow_file} even as root?"
                print(f"{COLOR_YELLOW}Warning: {msg}{COLOR_RESET}")
                add_finding_func(managed_findings, SEVERITY_MEDIUM, "Shadow File Read Error (as root)", msg)
                if not user_stats_local['error']: user_stats_local['error'] = msg
            except Exception as e:
                msg = f"Error analyzing {shadow_file}: {e}"
                print(f"{COLOR_RED}{msg}{COLOR_RESET}")
                add_finding_func(managed_findings, SEVERITY_HIGH, "Shadow File Analysis Error", msg)
                if not user_stats_local['error']: user_stats_local['error'] = msg
        else:
             add_finding_func(managed_findings, SEVERITY_INFO, "Shadow File Not Found", f"{shadow_file} not found.")
    else:
        add_finding_func(managed_findings, SEVERITY_INFO, "Shadow File Check Skipped", "Requires root privileges.")

    # --- /etc/sudoers Analysis ---
    sudoers_file = user_stats_local['sudoers_path']
    if os.geteuid() == 0:
        if os.path.exists(sudoers_file):
            try:
                with open(sudoers_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith( ('#', 'Defaults', 'User_Alias', 'Runas_Alias', 'Host_Alias', 'Cmnd_Alias') ): continue
                        # Use add_finding_func
                        if 'NOPASSWD:' in line:
                            rule_info = {'line_num': line_num, 'content': line, 'type': 'nopasswd'}
                            add_finding_func(managed_findings, SEVERITY_HIGH, f"Sudo NOPASSWD Entry Found", f"L{line_num} in {sudoers_file}: '{line}'.", "Review necessity, remove if possible.")
                            sudo_rules_list.append(rule_info)
                        # Basic broad ALL check - needs refinement
                        if re.search(r'^[^#%\s]+\s+ALL\s*=\s*(\(ALL(:ALL)?\)\s*)?ALL$', line, re.IGNORECASE):
                            rule_info = {'line_num': line_num, 'content': line, 'type': 'broad_all'}
                            add_finding_func(managed_findings, SEVERITY_MEDIUM, f"Potentially Broad Sudo Permissions", f"L{line_num} in {sudoers_file}: '{line}'.", "Review rule, grant specific commands instead.")
                            # Avoid adding duplicate if already caught by NOPASSWD
                            if rule_info not in sudo_rules_list:
                                sudo_rules_list.append(rule_info)
            except PermissionError:
                msg = f"Could not read {sudoers_file} even as root? Check permissions."
                print(f"{COLOR_YELLOW}Warning: {msg}{COLOR_RESET}")
                add_finding_func(managed_findings, SEVERITY_HIGH, "Sudoers File Read Error (as root)", msg)
                if not user_stats_local['error']: user_stats_local['error'] = msg
            except Exception as e:
                msg = f"Error analyzing {sudoers_file}: {e}"
                print(f"{COLOR_RED}{msg}{COLOR_RESET}")
                add_finding_func(managed_findings, SEVERITY_HIGH, "Sudoers File Analysis Error", msg)
                if not user_stats_local['error']: user_stats_local['error'] = msg
        else:
             add_finding_func(managed_findings, SEVERITY_INFO, "Sudoers File Not Found", f"{sudoers_file} not found.")
    else:
        add_finding_func(managed_findings, SEVERITY_INFO, "Sudoers Check Skipped", "Requires root privileges.")
    # Store collected list in local stats dict
    user_stats_local['sudo_rules'] = sudo_rules_list

    # Update managed stats at the end of the function
    managed_stats['users'] = user_stats_local 