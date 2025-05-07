#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Kernel Parameter Analysis (sysctl)
"""

import re
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH,
    run_command
)

def check_kernel_parameters(managed_stats, managed_findings, add_finding_func):
    """Checks sysctl params, storing results in managed dicts."""
    print(f"\n{COLOR_GREEN}[*] Checking Kernel Parameters (sysctl)...{COLOR_RESET}")
    kernel_stats_local = {'params': {}, 'errors': [], 'checked_count': 0}
    sysctl_cmd = ['sysctl', '-a']
    sysctl_output = run_command(sysctl_cmd)

    if sysctl_output is None:
        msg = "Could not execute 'sysctl -a'. Kernel parameter analysis skipped."
        add_finding_func(managed_findings, SEVERITY_HIGH, "Kernel Parameter Check Failed", msg, "Ensure 'sysctl' command available/executable.")
        print(f"{COLOR_RED}Error: Failed to run sysctl command.{COLOR_RESET}")
        kernel_stats_local['errors'].append(msg)
        managed_stats['kernel_params'] = kernel_stats_local
        return

    current_params = {}
    local_errors = [] # Aggregate errors locally
    for line in sysctl_output.strip().split('\n'):
        try:
            if '=' in line:
                key, value = line.split('=', 1)
                key, value = key.strip(), value.strip()
                current_params[key] = value
                kernel_stats_local['params'][key] = value # Store raw params locally
            # Use simpler regex extraction from previous fix attempt
            elif "Permission denied" in line:
                key = "Unknown key"
                match1 = re.search(r'reading key "([^"]+)"', line)
                match2 = re.search(r"cannot stat file \'([^\']+)\"", line)
                if match1: key = match1.group(1)
                elif match2: key = match2.group(1)
                error_msg = f"Permission denied reading {key}"
                if error_msg not in local_errors:
                    local_errors.append(error_msg)
                    add_finding_func(managed_findings, SEVERITY_LOW, "Kernel Parameter Permission Denied", f"Could not read sysctl key '{key}'. Run as root?", "Run as root for full check.")
            elif "No such file or directory" in line:
                key = "Unknown key"
                match1 = re.search(r'reading key "([^"]+)"', line)
                match2 = re.search(r"cannot stat file \'([^\']+)\"", line)
                if match1: key = match1.group(1)
                elif match2: key = match2.group(1)
                error_msg = f"Parameter not found: {key}"
                if error_msg not in local_errors: local_errors.append(error_msg)
            else:
                if line and "sysctl:" not in line:
                    error_msg = f"Unparsed sysctl line: {line}"
                    if error_msg not in local_errors: local_errors.append(error_msg)
        except Exception as e:
            error_msg = f"Error parsing sysctl line: {line} - {e}"
            print(f"{COLOR_RED}{error_msg}{COLOR_RESET}")
            if error_msg not in local_errors:
                 local_errors.append(error_msg)
                 add_finding_func(managed_findings, SEVERITY_MEDIUM, "Sysctl Parsing Error", f"Failed to parse: {line}")
    kernel_stats_local['errors'] = local_errors

    # Define Security Checks (remains the same)
    param_checks = {
        'kernel.randomize_va_space': {'expected_value': '2', 'severity': SEVERITY_MEDIUM, 'desc': 'ASLR not strongest (2). Current: {value}', 'rec': "Set kernel.randomize_va_space=2."},
        'net.ipv4.tcp_syncookies': {'expected_value': '1', 'severity': SEVERITY_MEDIUM, 'desc': 'TCP SYN Cookies disabled (Current: {value}). Risk of SYN floods.', 'rec': "Set net.ipv4.tcp_syncookies=1."},
        'net.ipv4.ip_forward': {'expected_value': '0', 'severity': SEVERITY_LOW, 'desc': 'IPv4 forwarding enabled (Current: {value}).', 'rec': "Set net.ipv4.ip_forward=0 if not router."},
        'net.ipv6.conf.all.forwarding': {'expected_value': '0', 'severity': SEVERITY_LOW, 'desc': 'IPv6 forwarding enabled (Current: {value}).', 'rec': "Set net.ipv6.conf.all.forwarding=0 if not router."},
        'net.ipv4.icmp_echo_ignore_broadcasts': {'expected_value': '1', 'severity': SEVERITY_LOW, 'desc': 'Responds to ICMP broadcasts (Current: {value}). Smurf risk.', 'rec': "Set net.ipv4.icmp_echo_ignore_broadcasts=1."},
        'net.ipv4.icmp_ignore_bogus_error_responses': {'expected_value': '1', 'severity': SEVERITY_LOW, 'desc': 'May process bogus ICMP errors (Current: {value}).', 'rec': "Set net.ipv4.icmp_ignore_bogus_error_responses=1."},
        'net.ipv4.conf.all.rp_filter': {'expected_value': '1', 'severity': SEVERITY_MEDIUM, 'desc': 'Reverse path filtering not strict (Current: {value}). Spoofing risk.', 'rec': "Set net.ipv4.conf.all.rp_filter=1."},
        'net.ipv4.conf.default.rp_filter': {'expected_value': '1', 'severity': SEVERITY_MEDIUM, 'desc': 'Default reverse path filtering not strict (Current: {value}).', 'rec': "Set net.ipv4.conf.default.rp_filter=1."},
        'net.ipv4.conf.all.log_martians': {'expected_value': '1', 'severity': SEVERITY_LOW, 'desc': 'Martian packet logging disabled (Current: {value}).', 'rec': "Set net.ipv4.conf.all.log_martians=1."},
        'net.ipv4.conf.all.accept_redirects': {'expected_value': '0', 'severity': SEVERITY_MEDIUM, 'desc': 'Accepts ICMP redirects (Current: {value}). MitM risk.', 'rec': "Set net.ipv4.conf.all.accept_redirects=0."},
        'net.ipv6.conf.all.accept_redirects': {'expected_value': '0', 'severity': SEVERITY_MEDIUM, 'desc': 'Accepts IPv6 ICMP redirects (Current: {value}).', 'rec': "Set net.ipv6.conf.all.accept_redirects=0."},
        'net.ipv4.conf.all.send_redirects': {'expected_value': '0', 'severity': SEVERITY_LOW, 'desc': 'May send ICMP redirects (Current: {value}).', 'rec': "Set net.ipv4.conf.all.send_redirects=0 if not router."},
        'kernel.yama.ptrace_scope': {'expected_value': '1', 'severity': SEVERITY_MEDIUM, 'desc': 'ptrace scope not restricted (Current: {value}). Value 0 insecure.', 'rec': "Set kernel.yama.ptrace_scope >= 1."},
        'kernel.sysrq': {'expected_value': '0', 'severity': SEVERITY_LOW, 'desc': 'Magic SysRq key enabled (Current: {value}).', 'rec': "Consider kernel.sysrq=0 or restrict functions."},
        'kernel.unprivileged_userns_clone': {'expected_value': '0', 'severity': SEVERITY_MEDIUM, 'desc': 'Unprivileged user ns enabled (Current: {value}). Increases attack surface.', 'rec': "Consider kernel.unprivileged_userns_clone=0 if not needed.", 'check_exists': True},
        'user.max_user_namespaces': {'expected_value': '0', 'severity': SEVERITY_MEDIUM, 'desc': 'User ns creation allowed (Current: {value}). Increases attack surface.', 'rec': "Consider user.max_user_namespaces=0 if not needed.", 'check_exists': True},
    }

    # Perform Checks using add_finding_func
    checked_params_count = 0
    for param, check in param_checks.items():
        if param in current_params:
            checked_params_count += 1
            value = current_params[param]
            expected = check['expected_value']
            mismatch = False
            if param == 'kernel.yama.ptrace_scope':
                try: mismatch = int(value) < 1
                except ValueError: mismatch = True
            elif param == 'kernel.sysrq':
                 try: mismatch = int(value) != 0
                 except ValueError: mismatch = True
            elif value != expected:
                 mismatch = True
            if mismatch:
                add_finding_func(managed_findings, check['severity'], f"Insecure Kernel Parameter: {param}", check['desc'].format(value=value), check['rec'])
            else:
                add_finding_func(managed_findings, SEVERITY_INFO, f"Kernel Parameter Check: {param}", f"Value '{value}' aligns with recommendations.")
        elif check.get('check_exists'): # Check if param that *should* exist is missing
             add_finding_func(managed_findings, SEVERITY_LOW, f"Kernel Parameter Not Found: {param}", f"Security parameter '{param}' not found. Check kernel support/config.", check['rec'])

    kernel_stats_local['checked_count'] = checked_params_count

    if kernel_stats_local['errors']:
         print(f"{COLOR_YELLOW}Warning: Encountered {len(kernel_stats_local['errors'])} errors/warnings reading sysctl values.{COLOR_RESET}")

    # Update managed stats at the end
    managed_stats['kernel_params'] = kernel_stats_local 