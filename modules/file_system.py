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

# Paths to exclude from all recursive scans more reliably
EXCLUDED_PATHS_PREFIXES = ('/proc/', '/sys/', '/dev/', '/run/') # Added /run

# --- Helper: Process Single File ---
def process_file(file_path, managed_stats, managed_findings, add_finding_func, sensitive_patterns, critical_file_patterns, common_suid_sgid_bins, existing_uids, existing_gids):
    """Helper to process a single file, adding findings via add_finding_func."""
    try:
        # Use lstat to avoid following symlinks for permission checks
        stat_info = os.lstat(file_path)
        mode = stat_info.st_mode
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        file_size = stat_info.st_size

        # Check 1: Sensitive Filename Pattern Match
        base_name = os.path.basename(file_path)
        is_critical_file_type = any(pattern.search(base_name) for pattern in critical_file_patterns)

        for pattern in sensitive_patterns:
            if pattern.search(base_name):
                # Default to LOW for generic sensitive patterns, MEDIUM if it's a critical type or non-zero size for specific interest files
                current_severity = SEVERITY_LOW
                if is_critical_file_type:
                    current_severity = SEVERITY_MEDIUM # If name matches critical list like .pem, .key, shadow
                elif file_size > 0 and any(p.search(base_name) for p in [
                    re.compile(r'^(.*backup|.*copy|.*\.bak|.*\.old)$', re.IGNORECASE), # Backups could be interesting
                    re.compile(r'config|conf|cfg', re.IGNORECASE), # Config files if they have content
                    re.compile(r'pass|secret|cred',re.IGNORECASE) # Filenames suggesting credentials
                ]):
                    current_severity = SEVERITY_MEDIUM

                # For truly critical files like shadow, check readability by others
                if base_name == "shadow" and (mode & stat.S_IROTH or mode & stat.S_IRGRP):
                    add_finding_func(managed_findings, SEVERITY_CRITICAL, "Readable Shadow File", f"Critical: \'{file_path}\' (shadow file) is readable by group or others ({oct(mode)[-3:]}).", "Restrict permissions immediately (chmod 640 or 600).")
                elif is_critical_file_type and file_size == 0: # e.g. empty .pem or .key file
                     add_finding_func(managed_findings, SEVERITY_INFO, "Potentially Sensitive File (Empty)", f"File \'{file_path}\' matches pattern \'{pattern.pattern}\' but is empty.", "Review if this file should exist.")
                elif current_severity >= SEVERITY_MEDIUM or (current_severity == SEVERITY_LOW and file_size > 0) : # Report non-empty LOW or any MEDIUM+
                    add_finding_func(managed_findings, current_severity, "Potentially Sensitive File Found", f"File \'{file_path}\' matches pattern \'{pattern.pattern}\'. Size: {file_size} bytes. Perms: {oct(mode)[-3:]}", "Review contents and permissions. Ensure least privilege.")
                # managed_stats['files']['sensitive_files_found'].append(file_path)
                break # Found one pattern, no need to check others for this category

        # Check 2: World-Writable Files
        if mode & stat.S_IWOTH: # Other write permission
            # Increase severity if owned by root or in critical dir
            path_lower = file_path.lower()
            is_in_sensitive_dir = any(path_lower.startswith(p) for p in ['/etc/', '/boot/', '/usr/lib/', '/lib/', '/bin/', '/sbin/'])
            if uid == 0 or is_in_sensitive_dir:
                add_finding_func(managed_findings, SEVERITY_CRITICAL, "Critical World-Writable File", f"File \'{file_path}\' is world-writable ({oct(mode)[-3:]}) and owned by root or in sensitive directory.", f"Remove world-writable permissions urgently (chmod o-w \'{file_path}\').")
            else:
                add_finding_func(managed_findings, SEVERITY_HIGH, "World-Writable File Found", f"File \'{file_path}\' is world-writable ({oct(mode)[-3:]}).", f"Remove world-writable permissions (chmod o-w \'{file_path}\').")
            # managed_stats['files']['world_writable_files'].append(file_path)

        # Check 3: SUID/SGID Files
        is_suid = mode & stat.S_ISUID
        is_sgid = mode & stat.S_ISGID
        # Only check regular files that are not symlinks
        if (is_suid or is_sgid) and stat.S_ISREG(mode) and not stat.S_ISLNK(mode):
            file_abs_path = os.path.abspath(file_path) # Ensure consistent path for set lookup
            is_common = file_abs_path in common_suid_sgid_bins
            
            type_str = "SUID" if is_suid else ""
            if is_sgid: type_str += " SGID" if type_str else "SGID"
            type_str = type_str.strip()

            # Check if SUID/SGID is in a non-standard/risky path like /tmp, /var/tmp, /home/*, /dev/shm
            is_in_risky_path = any(file_abs_path.startswith(p) for p in ['/tmp/', '/var/tmp/', '/home/', '/dev/shm/'])

            if mode & stat.S_IWOTH: # SUID/SGID and World Writable is CRITICAL
                 add_finding_func(managed_findings, SEVERITY_CRITICAL, f"CRITICAL: World-Writable {type_str} File", f"File \'{file_path}\' ({oct(mode)[-4:]}) is {type_str} AND world-writable.", f"Remove SUID/SGID (chmod u-s,g-s) or write permissions (o-w) IMMEDIATELY.")
            elif is_in_risky_path and not is_common:
                 add_finding_func(managed_findings, SEVERITY_CRITICAL, f"CRITICAL: {type_str} File in Risky Path", f"File \'{file_path}\' ({oct(mode)[-4:]}) is {type_str} and located in a risky path ({file_abs_path}).", f"Investigate immediately. Remove bit if unnecessary (chmod u-s/g-s \'{file_path}\').")
            elif not is_common:
                add_finding_func(managed_findings, SEVERITY_HIGH, f"Non-Standard {type_str} File Found", f"File \'{file_path}\' has {type_str} bit set ({oct(mode)[-4:]}). Not in common allowlist.", f"Investigate. Remove bit if unnecessary (chmod u-s/g-s \'{file_path}\').")
            else: # Common SUID/SGID
                 add_finding_func(managed_findings, SEVERITY_INFO, f"Standard {type_str} File Found", f"Common {type_str} file \'{file_path}\' ({oct(mode)[-4:]}). Verify integrity (e.g. via package manager).")

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
        uid = stat_info.st_uid
        # gid = stat_info.st_gid # Currently unused for dirs

        # Check 1: World-Writable Directory WITHOUT Sticky Bit
        is_world_writable = mode & stat.S_IWOTH
        has_sticky_bit = mode & stat.S_ISVTX

        # Exclude /tmp, /var/tmp, and /dev/shm from being flagged as HIGH/CRITICAL if they are world-writable
        # as this is often their standard configuration (though sticky bit is expected for /tmp and /var/tmp).
        # However, if they are world-writable AND MISSING STICKY BIT, it is a problem.
        is_common_tmp_path = dir_path in ['/tmp', '/var/tmp', '/dev/shm']

        if is_world_writable:
            if not has_sticky_bit:
                perms_octal = oct(mode)[-3:]
                # Directories like /dev/mqueue, /dev/pts are expected to be world-writable without sticky bit sometimes.
                # /run/lock is often 777 or 1777.
                # Check for specific known safe paths or patterns if necessary.
                if dir_path in ['/dev/mqueue', '/dev/pts'] or dir_path.startswith('/run/user/'): # Example known paths
                    add_finding_func(managed_findings, SEVERITY_INFO, "Expected World-Writable Directory (No Sticky Bit)", f"Directory '{dir_path}' ({perms_octal}) is world-writable without sticky bit, which is expected for this path.")
                elif is_common_tmp_path: # /tmp, /var/tmp, /dev/shm *without* sticky bit
                     add_finding_func(managed_findings, SEVERITY_HIGH, "World-Writable Temp Directory Missing Sticky Bit", f"Directory '{dir_path}' ({perms_octal}) is world-writable AND MISSING the sticky bit.", f"Set sticky bit (chmod +t '{dir_path}') to prevent users from deleting/renaming files they don\'t own.")
                elif uid == 0 and any(dir_path == p or dir_path.startswith(p + '/') for p in ['/', '/etc', '/usr', '/var', '/opt', '/srv', '/boot', '/lib', '/sbin', '/bin']):
                    add_finding_func(managed_findings, SEVERITY_HIGH, "Root-Owned Critical Path World-Writable (No Sticky Bit)", f"Directory '{dir_path}' ({perms_octal}) is root-owned, in a critical path, world-writable, and no sticky bit.", f"Critical: Remove world-write (chmod o-w) or set sticky bit (chmod +t '{dir_path}'). Review urgently.")
                else:
                    add_finding_func(managed_findings, SEVERITY_MEDIUM, "World-Writable Directory Found (No Sticky Bit)", f"Directory '{dir_path}' ({perms_octal}) is world-writable and no sticky bit.", f"Remove world-write (chmod o-w) or set sticky bit (chmod +t '{dir_path}').")
                # managed_stats['files']['world_writable_dirs_no_sticky'].append(dir_path)
            else: # World-writable WITH sticky bit
                 if is_common_tmp_path or dir_path.endswith('tmp'): # Common for /tmp, /var/tmp etc.
                    add_finding_func(managed_findings, SEVERITY_INFO, "World-Writable Directory (Sticky Bit Set - Expected)", f"Directory '{dir_path}' ({oct(mode)[-4:]}) is world-writable with sticky bit (e.g., /tmp behavior).")
                 else:
                    add_finding_func(managed_findings, SEVERITY_LOW, "World-Writable Directory (Sticky Bit Set)", f"Directory '{dir_path}' ({oct(mode)[-4:]}) is world-writable with sticky bit. Usually for shared directories like /tmp.", "Verify this is intended for non-tmp paths.")

        # Check 2: Dangling Directory Ownership (Add if needed, similar to file check)
        # Consider adding if existing_uids and existing_gids can be passed or accessed globally

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
        'sensitive_files_found': [], # This will be populated by titles, not just paths
        'world_writable_files': [],
        'world_writable_dirs_no_sticky': [],
        'suid_sgid_files': [],
        'dangling_files': [],
        'error': None
    }

    # --- Define Sensitive Patterns ---
    # These patterns are for files that *might* be interesting. Severity will often be LOW unless they also match critical_file_patterns or have credential-like names and content.
    sensitive_patterns = [
        # Configuration files (general) - often contain settings, less often direct keys unless poorly managed
        re.compile(r'\.(conf|cnf|config|cfg|ini|settings)$', re.IGNORECASE),
        # Shell script files - can contain hardcoded secrets or important logic
        re.compile(r'\.(sh|bash|zsh|ksh|csh|tcsh)$', re.IGNORECASE),
        # Python/Ruby/Perl scripts
        re.compile(r'\.(py|rb|pl)$', re.IGNORECASE),
        # Backup files - common place for old credentials or sensitive data
        re.compile(r'\.(bak|backup|old|save|~|swp|copy)$', re.IGNORECASE),
        # Log files - can contain sensitive operational data, sometimes credentials if verbose
        re.compile(r'\.log$', re.IGNORECASE),
        # SQL related files - dumps, schemas, connection configs
        re.compile(r'\.(sql|sqldump|sqlitedb|sqlite|db)$', re.IGNORECASE),
        # Files often containing lists of users, hosts, or credentials
        re.compile(r'^(passwd|group|hosts|htpasswd|netrc|secret_token|credentials|connections|service_account|api_key.*)', re.IGNORECASE),
        # Specific application config files that are known to sometimes store sensitive data
        re.compile(r'^(wp-config\.php|settings\.php|config\.inc\.php|localsettings\.php)$', re.IGNORECASE), # Web apps
        re.compile(r'^(otr\.private_key|secring\.gpg|pubring\.gpg)$', re.IGNORECASE), # GPG / OTR
        re.compile(r'(\.psql_history|\.mysql_history|\.bash_history|\.zsh_history|\.history)$', re.IGNORECASE), # History files
        re.compile(r'docker-compose\.yml', re.IGNORECASE), # Docker compose files
        # Generic names that might indicate sensitive content
        re.compile(r'(pass|secret|cred|token|key|private|auth|access|admin|backup|dump|config)', re.IGNORECASE),
    ]

    # These patterns identify file types that are almost always sensitive (private keys, certs, critical system files)
    # Matches here will typically result in higher severity findings.
    critical_file_patterns = [
        re.compile(r'\.pem$', re.IGNORECASE), re.compile(r'\.key$', re.IGNORECASE), # Private keys, certs
        re.compile(r'\.crt$', re.IGNORECASE), re.compile(r'\.cer$', re.IGNORECASE), # Certificates
        re.compile(r'id_(rsa|dsa|ecdsa|ed25519)$', re.IGNORECASE), # SSH private keys
        re.compile(r'shadow$', re.IGNORECASE), re.compile(r'sudoers$', re.IGNORECASE), # Critical system auth files
        re.compile(r'kdbx?$', re.IGNORECASE), re.compile(r'\.agilekeychain$', re.IGNORECASE), # Password manager databases
        re.compile(r'\.p12$', re.IGNORECASE), re.compile(r'\.pfx$', re.IGNORECASE), # Keystore files
        re.compile(r'secret_key_base', re.IGNORECASE), # Rails secret key
        re.compile(r'aws/credentials', re.IGNORECASE), re.compile(r'\.s3cfg$', re.IGNORECASE) # AWS credentials
    ]


    # Whitelist common system SUID/SGID binaries (use absolute paths)
    # This list should be periodically reviewed and updated.
    common_suid_sgid_bins = {
        # Core utils
        '/bin/mount', '/bin/su', '/bin/umount',
        '/usr/bin/at', '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/crontab',
        '/usr/bin/gpasswd', '/usr/bin/newgrp', '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/sudoedit',
        # Networking & System
        '/usr/sbin/pppd',
        '/usr/lib/openssh/ssh-keysign', # Varies by distro, e.g., /usr/libexec/openssh/ssh-keysign
        '/usr/lib/dbus-1.0/dbus-daemon-launch-helper', # Varies
        '/usr/lib/polkit-1/polkit-agent-helper-1', # pkexec's helper
        '/usr/bin/pkexec',
        # Xorg related, often SUID root but less of a direct shell vector
        '/usr/bin/X', '/usr/bin/Xorg',
        # Graphics driver helpers (less common now but historically)
        # '/usr/sbin/pam_timestamp_check', # Not a binary, but a helper for pam_timestamp
        # '/usr/sbin/unix_chkpwd', # Helper for pam_unix
        # Debian/Ubuntu specific paths for helpers
        '/sbin/mount.nfs', # Can be /usr/sbin/mount.nfs
        '/usr/lib/eject/dmcrypt-get-device',
        '/usr/lib/virtualbox/VBoxNetDHCP', '/usr/lib/virtualbox/VBoxNetNAT', '/usr/lib/virtualbox/VBoxHeadless',
        # RPM based paths
        '/usr/sbin/userhelper',
        # BSD variants might have different paths, e.g. /usr/libexec/auth/passwd
    }
    # Add common paths for helpers that might exist in different locations
    # Note: It's safer to verify these paths exist on the target before adding blindly
    # For example, ssh-keysign can be in /usr/libexec/openssh/ssh-keysign on some systems
    # For now, this list aims for common Linux distros.

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
                    process_file(base_path, fs_stats_local, managed_findings, add_finding_func, sensitive_patterns, critical_file_patterns, common_suid_sgid_bins, existing_uids, existing_gids)
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
                    if file_path.startswith(EXCLUDED_PATHS_PREFIXES):
                         continue
                    try:
                        inode = os.lstat(file_path).st_ino
                        if inode not in processed_inodes:
                            process_file(file_path, fs_stats_local, managed_findings, add_finding_func, sensitive_patterns, critical_file_patterns, common_suid_sgid_bins, existing_uids, existing_gids)
                            processed_inodes.add(inode)
                    except OSError: pass # Ignore stat errors

                # Process directories in the current directory (permission checks)
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    if dir_path.startswith(EXCLUDED_PATHS_PREFIXES):
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