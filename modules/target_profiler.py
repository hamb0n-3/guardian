#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Remote Target Profiler
"""

import socket
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_HIGH, SEVERITY_MEDIUM
)

COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5432, 5900, 8080, 8443
]

def profile_target(managed_stats, managed_findings, add_finding_func, target_host):
    """
    Profiles a remote target host by scanning common TCP ports and attempting banner grabbing.
    """
    print(f"{COLOR_GREEN}[*] Profiling target host: {target_host}...{COLOR_RESET}")

    target_profile_stats = {
        'target_host': target_host,
        'open_ports': [],
        'banners': {},
        'status': 'completed', # can be 'error'
        'error_message': None
    }

    # Attempt to resolve the target_host first to catch DNS issues early
    try:
        # This doesn't store the IP but validates the name and checks reachability at a basic level.
        # The actual IP used for connection will be resolved by socket.create_connection.
        socket.gethostbyname(target_host)
    except socket.gaierror as e:
        error_msg = f"DNS resolution failed for target {target_host}: {e}"
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, f"Target Profiling Error: {target_host}", error_msg, "Verify target hostname and DNS configuration.")
        target_profile_stats['status'] = 'error'
        target_profile_stats['error_message'] = error_msg
        # Ensure the base key for target_profiles exists
        if 'target_profiles' not in managed_stats:
            managed_stats['target_profiles'] = {} # This should be a manager.dict if created here by main
        managed_stats['target_profiles'][target_host] = target_profile_stats
        return
    except Exception as e: # Catch other unexpected errors during gethostbyname
        error_msg = f"Unexpected error resolving target {target_host}: {e}"
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, f"Target Profiling Error: {target_host}", error_msg)
        target_profile_stats['status'] = 'error'
        target_profile_stats['error_message'] = error_msg
        if 'target_profiles' not in managed_stats:
            managed_stats['target_profiles'] = {}
        managed_stats['target_profiles'][target_host] = target_profile_stats
        return


    for port in COMMON_TCP_PORTS:
        sock = None  # Ensure sock is defined for finally block
        try:
            # Set a timeout for the connection attempt (e.g., 1 second)
            sock = socket.create_connection((target_host, port), timeout=1.0)
            sock.settimeout(1.0) # Set timeout for subsequent operations like recv

            target_profile_stats['open_ports'].append(port)
            open_port_msg = f"Port {port}/TCP is open."
            add_finding_func(managed_findings, SEVERITY_INFO, f"Target {target_host}: Open Port", open_port_msg)
            
            # Attempt to grab a banner
            try:
                banner_data_raw = sock.recv(1024) # Receive up to 1024 bytes
                if banner_data_raw:
                    banner_data = banner_data_raw.decode('utf-8', errors='ignore').strip()
                    # Avoid storing overly long or purely binary non-decodable banners in stats if they are huge
                    # For findings, it's okay to truncate if necessary, but stats should be manageable.
                    # A simple strip might be enough for now.
                    if banner_data: # Ensure banner is not empty after strip
                        target_profile_stats['banners'][port] = banner_data
                        banner_finding_msg = f"Port {port}/TCP Banner: {banner_data[:100]}" # Truncate for display
                        if len(banner_data) > 100:
                            banner_finding_msg += "..."
                        add_finding_func(managed_findings, SEVERITY_INFO, f"Target {target_host}: Port Banner", banner_finding_msg)
            except socket.timeout:
                # No banner received within timeout, that's fine.
                pass
            except socket.error as e_recv:
                # Error during recv, could log this if needed.
                print(f"{COLOR_YELLOW}Warning: Could not receive banner from {target_host}:{port} - {e_recv}{COLOR_RESET}")
                pass # Continue, port is open, just no banner.

        except socket.timeout:
            # Connection timed out - port is likely closed or filtered
            pass
        except socket.error as e_conn:
            # Connection error (e.g., connection refused) - port is closed
            # print(f"Debug: Port {port} on {target_host} closed or filtered: {e_conn}") # Optional debug
            pass
        except Exception as e_outer:
            # Other unexpected errors
            error_msg = f"Unexpected error profiling {target_host}:{port} - {e_outer}"
            print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
            add_finding_func(managed_findings, SEVERITY_MEDIUM, f"Target Profiling Port Error: {target_host}:{port}", error_msg)
            if 'errors' not in target_profile_stats: # Initialize if not present
                target_profile_stats['errors'] = []
            target_profile_stats['errors'].append({port: str(e_outer)})
        finally:
            if sock:
                sock.close()

    # Store results in managed_stats
    # The caller (guardian.py wrapper) should ensure 'target_profiles' key exists and is a managed dict.
    if 'target_profiles' not in managed_stats:
        # This is a fallback, ideally initialized by the main script for multiprocess safety
        managed_stats['target_profiles'] = {} 
    managed_stats['target_profiles'][target_host] = target_profile_stats

    summary_msg = f"Target profiling for {target_host} completed. Open ports: {len(target_profile_stats['open_ports'])}. Banners grabbed: {len(target_profile_stats['banners'])}."
    print(f"{COLOR_GREEN}[+] {summary_msg}{COLOR_RESET}")
    add_finding_func(managed_findings, SEVERITY_INFO, f"Target Profiling Summary: {target_host}", summary_msg)


if __name__ == '__main__':
    # Example Usage (requires a mock environment for managed_stats, managed_findings, add_finding_func)
    print("This module is intended to be run as part of the Guardian scanner.")
    
    # Mock objects for standalone testing (simplified)
    class MockManagerDict(dict):
        pass # Behaves like a dict for this simple test

    class MockManagerList:
        def __init__(self):
            self._list = []
        def append(self, item):
            self._list.append(item)
        def __repr__(self):
            return repr(self._list)

    mock_findings_store = {
        SEVERITY_INFO: MockManagerList(),
        SEVERITY_MEDIUM: MockManagerList(),
        SEVERITY_HIGH: MockManagerList()
    }
    mock_stats_store = MockManagerDict()
    # Pre-initialize 'target_profiles' as the main script would
    mock_stats_store['target_profiles'] = MockManagerDict()


    def mock_add_finding(findings_dict, severity, title, description, recommendation="N/A"):
        print(f"  FINDING [{severity}]: {title} - {description} (Rec: {recommendation})")
        if severity in findings_dict:
            findings_dict[severity].append({'title': title, 'description': description, 'recommendation': recommendation})

    # --- Test target_profiler ---
    print("\n--- Running Mock Target Profiling ---")
    # To test this locally, you might need to set up a simple server on some ports
    # e.g., `nc -lvp 8080` or use an actual reachable host.
    # Using "localhost" or "127.0.0.1" for testing.
    test_target = "127.0.0.1" 
    # test_target = "scanme.nmap.org" # For external testing (be responsible)

    print(f"Mock profiling target: {test_target}")
    try:
        profile_target(mock_stats_store, mock_findings_store, mock_add_finding, test_target)
    except Exception as e:
        print(f"Error during mock target profiling: {e}")
    
    print("\n--- Mock Stats for Target Profiler ---")
    if test_target in mock_stats_store['target_profiles']:
        profile_data = mock_stats_store['target_profiles'][test_target]
        for key, value in profile_data.items():
            if key == 'banners' and isinstance(value, dict):
                print(f"  Banners Found: {len(value)}")
                for port, banner in value.items():
                    print(f"    Port {port}: {banner[:60]}...") # Print first 60 chars
            elif key == 'open_ports' and isinstance(value, list):
                 print(f"  Open Ports: {value}")
            else:
                print(f"  {key}: {value}")
    else:
        print(f"  No profile data found for {test_target} in mock_stats_store.")


    print("\n--- Mock Findings from Target Profiler ---")
    for severity, findings_list in mock_findings_store.items():
        if findings_list._list:
            print(f"  {severity.upper()} Findings:")
            for finding in findings_list._list:
                print(f"    - {finding['title']}")
    
    print("\nNote: Standalone test provides limited insight. Full functionality within Guardian.")
