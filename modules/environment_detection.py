#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Environment Detection (Containers/VMs)

Detects if running inside a container or virtual machine.
"""

import os
import re
import subprocess # Needed for direct call
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
    run_command
)

# --- Environment Detection Functions ---

def detect_environment(managed_stats, managed_findings, add_finding_func):
    """Detects container/VM environment and stores findings/stats."""
    print(f"\n{COLOR_GREEN}[*] Detecting Execution Environment (Container/VM)...{COLOR_RESET}")
    env_stats_local = {
        'detection_type': 'unknown',
        'details': [],
        'error': None
    }
    detected = False

    # --- Check using systemd-detect-virt ---
    try:
        cmd_detect_virt = ['systemd-detect-virt', '--quiet']
        process = subprocess.run(cmd_detect_virt, capture_output=True, text=True, timeout=5, check=False)

        if process.returncode == 0 and process.stdout.strip():
            virt_type = process.stdout.strip()
            env_stats_local['detection_type'] = virt_type
            env_stats_local['details'].append(f"systemd-detect-virt reported: {virt_type}")
            add_finding_func(managed_findings, SEVERITY_INFO, "Virtualization Detected (systemd)", f"Type: {virt_type}")
            detected = True
        elif process.returncode != 0 and "command not found" not in process.stderr.lower() and "could not be determined" not in process.stderr.lower() :
            env_stats_local['detection_type'] = 'physical'
            env_stats_local['details'].append("systemd-detect-virt indicates physical host or unrecognized VM.")
            add_finding_func(managed_findings, SEVERITY_INFO, "Environment Type (systemd)", "Physical host or unrecognized virtualization.")
            detected = True

    except FileNotFoundError:
        env_stats_local['details'].append("systemd-detect-virt command not found.")
    except subprocess.TimeoutExpired:
        msg = "systemd-detect-virt command timed out."
        print(f"{COLOR_YELLOW}Warning: {msg}{COLOR_RESET}")
        if not env_stats_local['error']: env_stats_local['error'] = msg
    except Exception as e:
        msg = f"Error running systemd-detect-virt: {e}"
        print(f"{COLOR_YELLOW}Warning: {msg}{COLOR_RESET}")
        if not env_stats_local['error']: env_stats_local['error'] = msg

    # --- Docker Check ---
    if not detected and os.path.exists('/.dockerenv'):
        env_stats_local['detection_type'] = 'docker'
        env_stats_local['details'].append("Found /.dockerenv file.")
        add_finding_func(managed_findings, SEVERITY_INFO, "Container Detected", "Docker environment likely (/.dockerenv exists).")
        detected = True

    # --- CGroup Check ---
    if not detected and os.path.exists('/proc/self/cgroup'):
        try:
            with open('/proc/self/cgroup', 'r') as f:
                cgroup_content = f.read()
                if 'docker' in cgroup_content:
                    env_stats_local['detection_type'] = 'docker'
                    env_stats_local['details'].append("'docker' found in /proc/self/cgroup.")
                    add_finding_func(managed_findings, SEVERITY_INFO, "Container Detected", "Docker environment likely (cgroup check).")
                    detected = True
                elif 'lxc' in cgroup_content:
                    env_stats_local['detection_type'] = 'lxc'
                    env_stats_local['details'].append("'lxc' found in /proc/self/cgroup.")
                    add_finding_func(managed_findings, SEVERITY_INFO, "Container Detected", "LXC environment likely (cgroup check).")
                    detected = True
        except Exception as e:
            msg = f"Error checking /proc/self/cgroup: {e}"
            print(f"{COLOR_YELLOW}Warning: {msg}{COLOR_RESET}")
            if not env_stats_local['error']: env_stats_local['error'] = msg

    # --- DMI/Hardware Checks (Root often needed) ---
    if not detected and os.geteuid() == 0:
        dmi_checks = {
            'VMware': 'vmware',
            'VirtualBox': 'virtualbox',
            'KVM': 'kvm',
            'QEMU': 'qemu',
            'Microsoft Corporation': 'hyper-v'
        }
        dmi_info = None
        dmi_files = ['/sys/class/dmi/id/product_name', '/sys/class/dmi/id/sys_vendor']
        try:
            for dmi_file in dmi_files:
                 if os.path.exists(dmi_file):
                      with open(dmi_file, 'r') as f:
                           dmi_info = f.read()
                           if dmi_info: break
            if dmi_info:
                 for pattern, virt_type in dmi_checks.items():
                      if pattern.lower() in dmi_info.lower():
                           env_stats_local['detection_type'] = virt_type
                           env_stats_local['details'].append(f"DMI info ('{pattern}') suggests {virt_type}.")
                           add_finding_func(managed_findings, SEVERITY_INFO, "Virtualization Detected (DMI)", f"Type: {virt_type} (based on DMI strings).", f"Path: {dmi_file}")
                           detected = True
                           break
        except Exception as e:
             msg = f"Error reading DMI files ({dmi_files}): {e}"
             print(f"{COLOR_YELLOW}Warning: {msg}{COLOR_RESET}")

        # Fallback to dmidecode command
        if not detected:
            try:
                cmd_dmi = ['dmidecode', '-t', 'system']
                dmi_output = run_command(cmd_dmi)
                if dmi_output:
                    for pattern, virt_type in dmi_checks.items():
                        if pattern.lower() in dmi_output.lower():
                            env_stats_local['detection_type'] = virt_type
                            env_stats_local['details'].append(f"dmidecode output ('{pattern}') suggests {virt_type}.")
                            add_finding_func(managed_findings, SEVERITY_INFO, "Virtualization Detected (dmidecode)", f"Type: {virt_type} (based on dmidecode output).")
                            detected = True
                            break
            except Exception as e:
                 print(f"{COLOR_YELLOW}Info: dmidecode check failed (Error: {e}). May need install or root.{COLOR_RESET}")

    # --- Final Determination ---
    if not detected and env_stats_local['detection_type'] == 'unknown':
         env_stats_local['detection_type'] = 'physical (assumed)'
         env_stats_local['details'].append("No specific container/VM detected; assuming physical or unrecognized.")
         add_finding_func(managed_findings, SEVERITY_INFO, "Environment Type", "Assumed physical host (no specific container/VM detected).")

    managed_stats['environment'] = env_stats_local
