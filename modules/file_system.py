#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: File System Analysis (Sensitive Files, Permissions)
"""

import os
import re
import stat # For permission constants like S_IWOTH, S_ISUID, S_ISGID, S_ISVTX
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH
)

# --- Helper: Process Single File ---
def process_file(file_path, managed_stats, managed_findings, add_finding_func, sensitive_patterns, common_suid_sgid_bins, existing_uids, existing_gids):
    """Helper to process a single file, adding findings via add_finding_func."""
    try:
        # Use lstat to avoid following symlinks for permission checks
        stat_info = os.lstat(file_path)
        mode = stat_info.st_mode
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        file_size = stat_info.st_size

        # Check 1: Sensitive Filename Pattern Match
        for pattern in sensitive_patterns:
            if pattern.search(os.path.basename(file_path)):
                is_potentially_critical = any(p.search(os.path.basename(file_path)) for p in [
                    re.compile(r'\.pem$', re.IGNORECASE), re.compile(r'\.key$', re.IGNORECASE),
                    re.compile(r'id_rsa$', re.IGNORECASE), re.compile(r'shadow$', re.IGNORECASE)])
                if file_size > 0 or is_potentially_critical:
                    add_finding_func(managed_findings, SEVERITY_MEDIUM, "Potentially Sensitive File Found", f"File '{file_path}' matches pattern '{pattern.pattern}'. Size: {file_size} bytes.", "Review contents and permissions.")
                    # Need to append to managed list safely
                    # This requires managed_stats['files'] to be initialized as manager.dict()
                    # and lists within it also managed lists, or careful updates.
                    # Let's update a local list first and assign at the end of the main function.
                    # managed_stats['files']['sensitive_files_found'].append(file_path) # This is NOT process-safe if managed_stats['files'] is just a normal dict
                    break

        # Check 2: World-Writable Files
        if mode & stat.S_IWOTH: # Other write permission
            add_finding_func(managed_findings, SEVERITY_HIGH, "World-Writable File Found", f"File '{file_path}' is world-writable ({oct(mode)[-3:]}).", f"Remove world-writable permissions (chmod o-w '{file_path}').")
            # managed_stats['files']['world_writable_files'].append(file_path)

        # Check 3: SUID/SGID Files
        is_suid = mode & stat.S_ISUID
        is_sgid = mode & stat.S_ISGID
        # Only check regular files that are not symlinks
        if (is_suid or is_sgid) and stat.S_ISREG(mode) and not stat.S_ISLNK(mode):
            if file_path not in common_suid_sgid_bins:
                type_str = "SUID" if is_suid else ""
                if is_sgid: type_str += " SGID" if type_str else "SGID"
                add_finding_func(managed_findings, SEVERITY_HIGH, f"Non-Standard {type_str.strip()} File Found", f"File '{file_path}' has {type_str.strip()} bit set ({oct(mode)[-4:]}).", f"Investigate. Remove bit if unnecessary (chmod u-s/g-s '{file_path}').")
                # managed_stats['files']['suid_sgid_files'].append(file_path)
            else:
                 add_finding_func(managed_findings, SEVERITY_INFO, f"Standard SUID/SGID File Found", f"Common SUID/SGID file '{file_path}' ({oct(mode)[-4:]}). Verify integrity.")

        # Check 4: Dangling File Ownership
        owner_missing = uid not in existing_uids if existing_uids else False
        group_missing = gid not in existing_gids if existing_gids else False
        if owner_missing or group_missing:
             reason = []
             if owner_missing: reason.append("Owner UID")
             if group_missing: reason.append("Group GID")
             add_finding_func(managed_findings, SEVERITY_LOW, f"File with Dangling Ownership Found", f"File '{file_path}' has unknown {' and '.join(reason)}: UID={uid}, GID={gid}.", "Consider removing file or changing ownership.")
             # managed_stats['files']['dangling_files'].append(file_path)

    except FileNotFoundError:
        pass # File might disappear during scan
    except PermissionError:
        pass # Ignore permission errors for individual files during walk
    except Exception as e:
        print(f"{COLOR_RED}Error processing file {file_path}: {e}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_LOW, "File Processing Error", f"Could not process file '{file_path}': {e}")

# --- Helper: Process Single Directory ---
def process_directory(dir_path, managed_stats, managed_findings, add_finding_func):
    """Helper to process directory permissions, adding findings via add_finding_func."""
    try:
        stat_info = os.lstat(dir_path) # Use lstat for directories too
        mode = stat_info.st_mode
        # uid = stat_info.st_uid # Currently unused for dirs
        # gid = stat_info.st_gid # Currently unused for dirs

        # Check 1: World-Writable Directory WITHOUT Sticky Bit
        is_world_writable = mode & stat.S_IWOTH
        has_sticky_bit = mode & stat.S_ISVTX
        if is_world_writable and not has_sticky_bit:
            # Common exceptions like /dev/mqueue might be world-writable without sticky bit
            # Refine exceptions as needed
            if dir_path not in ['/dev/mqueue']: # Add more known safe examples if necessary
                add_finding_func(managed_findings, SEVERITY_MEDIUM, "World-Writable Directory Found (No Sticky Bit)", f"Directory '{dir_path}' is world-writable ({oct(mode)[-3:]}) and no sticky bit.", f"Remove world-write (chmod o-w) or set sticky bit (chmod +t '{dir_path}').")
                # managed_stats['files']['world_writable_dirs_no_sticky'].append(dir_path)
        elif is_world_writable and has_sticky_bit:
             add_finding_func(managed_findings, SEVERITY_INFO, "World-Writable Directory (Sticky Bit Set)", f"Directory '{dir_path}' ({oct(mode)[-4:]}) has sticky bit (e.g., /tmp).")

        # Check 2: Dangling Directory Ownership (Add if needed, similar to file check)

    except FileNotFoundError:
         pass
    except PermissionError:
         pass # Ignore permission errors for dirs during walk
    except Exception as e:
        print(f"{COLOR_RED}Error processing directory {dir_path}: {e}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_LOW, "Directory Processing Error", f"Could not process directory '{dir_path}': {e}")


# --- Main File System Scan Function ---
def find_sensitive_files_and_permissions(managed_stats, managed_findings, add_finding_func, search_paths=None, max_depth=5):
    """Searches FS for sensitive files/permissions, storing results in managed dicts."""
    print(f"\n{COLOR_GREEN}[*] Searching for Sensitive Files and Insecure Permissions...{COLOR_RESET}")

    # Define default search paths if none provided
    if search_paths is None:
        search_paths = ['/etc', '/var', '/home', '/root', '/opt', '/srv', '/tmp', '/var/tmp']
        if os.path.isdir('/var/www'): search_paths.append('/var/www')
        if os.path.isdir('/usr/local/www'): search_paths.append('/usr/local/www')
        # Add other common paths like /usr/local/etc, etc.

    print(f"  Search Paths: {search_paths}")
    print(f"  Max Depth: {max_depth}")

    # Initialize local lists to aggregate results before updating managed_stats
    # This avoids numerous small writes to the managed dictionary from helpers
    fs_stats_local = {
        'search_paths': search_paths,
        'sensitive_files_found': [],
        'world_writable_files': [],
        'world_writable_dirs_no_sticky': [],
        'suid_sgid_files': [],
        'dangling_files': [],
        'error': None
    }

    # --- Define Sensitive Patterns ---
    sensitive_patterns = [
        re.compile(r'\.pem$', re.IGNORECASE), re.compile(r'\.key$', re.IGNORECASE),
        re.compile(r'\.crt$', re.IGNORECASE), re.compile(r'\.cer$', re.IGNORECASE),
        re.compile(r'id_rsa$', re.IGNORECASE), re.compile(r'id_dsa$', re.IGNORECASE), re.compile(r'id_ecdsa$', re.IGNORECASE), re.compile(r'id_ed25519$', re.IGNORECASE),
        re.compile(r'known_hosts$', re.IGNORECASE), re.compile(r'authorized_keys$', re.IGNORECASE),
        re.compile(r'\.cscfg$', re.IGNORECASE), re.compile(r'\.rdp$', re.IGNORECASE),
        re.compile(r'\.sql$', re.IGNORECASE), re.compile(r'\.sqldump$', re.IGNORECASE), re.compile(r'dump\.sql', re.IGNORECASE),
        re.compile(r'\.config$', re.IGNORECASE), re.compile(r'\.conf$', re.IGNORECASE), re.compile(r'\.cfg$', re.IGNORECASE),
        re.compile(r'\.xml$', re.IGNORECASE), re.compile(r'\.json$', re.IGNORECASE), re.compile(r'\.yaml$', re.IGNORECASE), re.compile(r'\.yml$', re.IGNORECASE),
        re.compile(r'\.sh$', re.IGNORECASE), re.compile(r'\.bash$', re.IGNORECASE), re.compile(r'\.py$', re.IGNORECASE), re.compile(r'\.pl$', re.IGNORECASE), re.compile(r'\.rb$', re.IGNORECASE),
        re.compile(r'\.log$', re.IGNORECASE),
        re.compile(r'password', re.IGNORECASE), re.compile(r'secret', re.IGNORECASE), re.compile(r'credential', re.IGNORECASE), re.compile(r'private', re.IGNORECASE),
        re.compile(r'\.bak$', re.IGNORECASE), re.compile(r'\.old$', re.IGNORECASE), re.compile(r'\.tmp$', re.IGNORECASE), re.compile(r'\.swp$', re.IGNORECASE),
        re.compile(r'\.htpasswd$', re.IGNORECASE), re.compile(r'\.netrc$', re.IGNORECASE),
        re.compile(r'shadow$', re.IGNORECASE), re.compile(r'passwd$', re.IGNORECASE), re.compile(r'sudoers$', re.IGNORECASE),
        re.compile(r'kdbx?$', re.IGNORECASE), re.compile(r'\.agilekeychain$', re.IGNORECASE),
    ]

    # Whitelist common system SUID/SGID binaries
    common_suid_sgid_bins = {
        '/bin/mount', '/bin/umount', '/bin/su', '/usr/bin/sudo', '/usr/bin/passwd',
        '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/gpasswd', '/usr/bin/newgrp',
        '/usr/lib/openssh/ssh-keysign', '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
        '/usr/sbin/unix_chkpwd', '/usr/bin/crontab', '/usr/sbin/pppd', '/usr/bin/at',
        '/sbin/mount.nfs', '/sbin/unix_chkpwd', '/sbin/pam_timestamp_check' # Add more based on distribution
    }

    # Get existing UIDs and GIDs to check for dangling files
    existing_uids, existing_gids = set(), set()
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                fields = line.strip().split(':')
                if len(fields) >= 3:
                    try: existing_uids.add(int(fields[2]))
                    except ValueError: pass
        with open('/etc/group', 'r') as f:
            for line in f:
                fields = line.strip().split(':')
                if len(fields) >= 3:
                    try: existing_gids.add(int(fields[2]))
                    except ValueError: pass
    except Exception as e:
        print(f"{COLOR_YELLOW}Warning: Could not read /etc/passwd or /etc/group to check for dangling file ownership: {e}{COLOR_RESET}")
        # Continue without dangling checks if files are unreadable
        existing_uids, existing_gids = None, None
        if not fs_stats_local['error']: fs_stats_local['error'] = f"Could not read /etc/passwd or /etc/group to check for dangling file ownership: {e}"

    # --- Walk Filesystem ---
    processed_inodes = set() # Avoid processing same file/dir multiple times if symlinks exist
    for base_path in search_paths:
        if not os.path.exists(base_path):
            print(f"{COLOR_YELLOW}Warning: Search path {base_path} does not exist. Skipping.{COLOR_RESET}")
            continue

        if os.path.isfile(base_path):
            try:
                inode = os.lstat(base_path).st_ino
                if inode not in processed_inodes:
                    # Pass local stats dict for helpers to append to
                    process_file(base_path, fs_stats_local, managed_findings, add_finding_func, sensitive_patterns, common_suid_sgid_bins, existing_uids, existing_gids)
                    processed_inodes.add(inode)
            except OSError: pass # Ignore stat errors here
            continue

        # Use os.walk with limited depth and error handling
        try:
            for root, dirs, files in os.walk(base_path, topdown=True, onerror=lambda err: print(f"{COLOR_YELLOW}Warning: Error accessing {err.filename}: {err.strerror}{COLOR_RESET}")):
                # --- Depth Limiting ---
                # Calculate depth relative to the *current* base_path being walked
                depth = root[len(base_path):].count(os.sep)
                if base_path == '/': # Adjust for root path calculation
                     depth = root.count(os.sep)
                else:
                    # Ensure trailing slash consistency for accurate counting
                    root_rel = root.replace(base_path, '', 1)
                    depth = root_rel.count(os.sep)

                # Prune directories beyond max_depth
                if depth >= max_depth:
                    dirs[:] = [] # Don't descend further
                    continue # Skip processing files/dirs at this level if already >= max_depth

                # Process files in the current directory
                for file in files:
                    file_path = os.path.join(root, file)
                    # Avoid rescanning /proc, /sys, /dev unless explicitly requested
                    # This basic check might need refinement.
                    if any(part in file_path for part in ['/proc/', '/sys/', '/dev/']): 
                         continue
                    try:
                        inode = os.lstat(file_path).st_ino
                        if inode not in processed_inodes:
                            process_file(file_path, fs_stats_local, managed_findings, add_finding_func, sensitive_patterns, common_suid_sgid_bins, existing_uids, existing_gids)
                            processed_inodes.add(inode)
                    except OSError: pass # Ignore stat errors

                # Process directories in the current directory (permission checks)
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    if any(part in dir_path for part in ['/proc/', '/sys/', '/dev/']):
                         continue
                    try:
                        inode = os.lstat(dir_path).st_ino
                        if inode not in processed_inodes:
                             process_directory(dir_path, fs_stats_local, managed_findings, add_finding_func)
                             processed_inodes.add(inode)
                    except OSError: pass # Ignore stat errors
        except Exception as walk_e:
            msg = f"Error walking directory {base_path}: {walk_e}"
            print(f"{COLOR_RED}{msg}{COLOR_RESET}")
            add_finding_func(managed_findings, SEVERITY_HIGH, "File System Walk Error", msg)
            if not fs_stats_local['error']: fs_stats_local['error'] = msg

    # Update managed_stats with the aggregated results from local dict
    managed_stats['files'] = fs_stats_local

    if fs_stats_local['error']:
        add_finding_func(managed_findings, SEVERITY_LOW, "File System Scan Error", fs_stats_local['error']) 