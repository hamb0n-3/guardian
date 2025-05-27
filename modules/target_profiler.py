#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: Remote Target Profiler
"""

import socket
import ssl
import http.client
from datetime import datetime
from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_CRITICAL
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
        
        # If port 443 is found open, perform SSL/TLS analysis
        if port == 443 and port in target_profile_stats['open_ports']:
            analyze_ssl_tls_certificate(managed_stats, managed_findings, add_finding_func, target_host, port=443)


    # Store results in managed_stats
    # The caller (guardian.py wrapper) should ensure 'target_profiles' key exists and is a managed dict.
    if 'target_profiles' not in managed_stats:
        # This is a fallback, ideally initialized by the main script for multiprocess safety
        managed_stats['target_profiles'] = {} 
    managed_stats['target_profiles'][target_host] = target_profile_stats

    summary_msg = f"Target profiling for {target_host} completed. Open ports: {len(target_profile_stats['open_ports'])}. Banners grabbed: {len(target_profile_stats['banners'])}."
    print(f"{COLOR_GREEN}[+] {summary_msg}{COLOR_RESET}")
    add_finding_func(managed_findings, SEVERITY_INFO, f"Target Profiling Summary: {target_host}", summary_msg)


def analyze_ssl_tls_certificate(managed_stats, managed_findings, add_finding_func, target_host, port=443):
    """Analyzes SSL/TLS certificate for a given target and port."""
    print(f"{COLOR_GREEN}[*] Analyzing SSL/TLS certificate for {target_host}:{port}...{COLOR_RESET}")

    ssl_stats = {
        'target_host': target_host,
        'port': port,
        'status': 'completed',
        'error_message': None,
        'certificate_details': {},
        'hsts_header': None,
        'warnings': [], # For non-critical issues like self-signed if that's not an error
        'hostname_match': None
    }

    try:
        context = ssl.create_default_context()
        # Disable hostname checking in wrap_socket, we'll do it manually
        # context.check_hostname = False 
        # context.verify_mode = ssl.CERT_NONE # Also disable cert validation for now to get cert first

        # SNI (Server Name Indication) is important for getting the correct certificate from a server hosting multiple sites.
        # socket.create_connection handles name resolution.
        with socket.create_connection((target_host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            ssl_stats['status'] = 'error'
            ssl_stats['error_message'] = "No certificate received from peer."
            add_finding_func(managed_findings, SEVERITY_HIGH, f"SSL/TLS Certificate Error: {target_host}:{port}", ssl_stats['error_message'])
            # Store stats before returning
            if 'target_profiles' in managed_stats and target_host in managed_stats['target_profiles']:
                managed_stats['target_profiles'][target_host]['ssl_tls_analysis'] = ssl_stats
            return

        # Parse Certificate Details
        subject_tuples = cert.get('subject', ())
        issuer_tuples = cert.get('issuer', ())
        
        subject_cn = None
        for rdn in subject_tuples: # Each RDN is a tuple of AVAs
            for ava in rdn: # Each AVA is a (type, value) pair
                if ava[0] == 'commonName':
                    subject_cn = ava[1]
                    break
            if subject_cn: break
        
        issuer_cn = None
        for rdn in issuer_tuples:
            for ava in rdn:
                if ava[0] == 'commonName':
                    issuer_cn = ava[1]
                    break
            if issuer_cn: break

        ssl_stats['certificate_details'] = {
            'subject': dict(x[0] for x in sum(subject_tuples, ())), # Simplified subject dict
            'issuer': dict(x[0] for x in sum(issuer_tuples, ())),   # Simplified issuer dict
            'subject_cn': subject_cn,
            'issuer_cn': issuer_cn,
            'version': cert.get('version'),
            'serialNumber': cert.get('serialNumber'),
            'notBefore': cert.get('notBefore'),
            'notAfter': cert.get('notAfter'),
            'subjectAltName': cert.get('subjectAltName', [])
        }
        add_finding_func(managed_findings, SEVERITY_INFO, f"SSL Cert Subject: {target_host}:{port}", f"CN: {subject_cn}, Subject: {ssl_stats['certificate_details']['subject']}")
        add_finding_func(managed_findings, SEVERITY_INFO, f"SSL Cert Issuer: {target_host}:{port}", f"CN: {issuer_cn}, Issuer: {ssl_stats['certificate_details']['issuer']}")
        add_finding_func(managed_findings, SEVERITY_INFO, f"SSL Cert Validity: {target_host}:{port}", f"Not Before: {cert.get('notBefore')}, Not After: {cert.get('notAfter')}")


        # Hostname Verification
        target_matches_cn = subject_cn == target_host
        target_matches_san = any(entry[1] == target_host for entry in cert.get('subjectAltName', []) if entry[0].lower() == 'dns')
        
        ssl_stats['hostname_match'] = target_matches_cn or target_matches_san
        if not ssl_stats['hostname_match']:
            ssl_stats['warnings'].append("Hostname mismatch")
            add_finding_func(managed_findings, SEVERITY_CRITICAL, f"Certificate Hostname Mismatch: {target_host}:{port}",
                             f"Target '{target_host}' does not match CN ('{subject_cn}') or SANs ({cert.get('subjectAltName', [])}).",
                             "This is a strong indicator of a potential MiTM attack or misconfiguration. Do not trust this connection.")
        else:
            add_finding_func(managed_findings, SEVERITY_INFO, f"Certificate Hostname Verification: {target_host}:{port}", "Successful.")

        # Validity Period
        try:
            # Format: 'MMM DD HH:MM:SS YYYY GMT' - e.g. 'Jul 22 12:00:00 2024 GMT'
            # Python's strptime does not handle GMT/UTC timezone abbreviations directly in %Z on all platforms.
            # OpenSSL's getpeercert() format is fixed, so we assume GMT.
            # Strip ' GMT' and parse, then make timezone-aware (UTC).
            not_before_str = cert.get('notBefore', '')
            not_after_str = cert.get('notAfter', '')

            # Example: 'Jul 22 00:00:00 2023 GMT'
            date_format = "%b %d %H:%M:%S %Y" # GMT is implicit

            if not_before_str.endswith(" GMT"): not_before_str = not_before_str[:-4]
            if not_after_str.endswith(" GMT"): not_after_str = not_after_str[:-4]

            dt_not_before = datetime.strptime(not_before_str, date_format)
            dt_not_after = datetime.strptime(not_after_str, date_format)
            
            now = datetime.utcnow() # Use UTC for comparison
            if now < dt_not_before:
                ssl_stats['warnings'].append("Certificate not yet valid")
                add_finding_func(managed_findings, SEVERITY_HIGH, f"Certificate Not Yet Valid: {target_host}:{port}", f"Valid from: {cert.get('notBefore')}")
            if now > dt_not_after:
                ssl_stats['warnings'].append("Certificate expired")
                add_finding_func(managed_findings, SEVERITY_HIGH, f"Certificate Expired: {target_host}:{port}", f"Expired on: {cert.get('notAfter')}")
        except ValueError as ve:
            ssl_stats['warnings'].append(f"Could not parse certificate validity dates: {ve}")
            add_finding_func(managed_findings, SEVERITY_LOW, f"Certificate Date Parsing Error: {target_host}:{port}", f"Dates: '{cert.get('notBefore')}', '{cert.get('notAfter')}'. Error: {ve}")


        # Self-Signed Check (Heuristic)
        # Compare the RDNSequence of subject and issuer. Direct dict comparison can be tricky due to ordering.
        # A common heuristic is if the CNs match AND other key fields are similar, or simply if subject == issuer.
        # The getpeercert() dict structure for subject/issuer is a tuple of tuples of tuples.
        # Example: ( (('countryName', 'US'),), (('stateOrProvinceName', 'CA'),), ... )
        if cert.get('subject') == cert.get('issuer'):
            ssl_stats['warnings'].append("Certificate appears self-signed")
            add_finding_func(managed_findings, SEVERITY_MEDIUM, f"Self-Signed Certificate: {target_host}:{port}",
                             "The certificate issuer is the same as the subject. This is typical for self-signed certificates.",
                             "Verify if this is expected. Self-signed certificates are common in private networks but not for public-facing services.")

    except socket.gaierror as e:
        ssl_stats['status'] = 'error'
        ssl_stats['error_message'] = f"DNS resolution failed: {e}"
    except socket.timeout as e:
        ssl_stats['status'] = 'error'
        ssl_stats['error_message'] = f"Connection timed out: {e}"
    except ssl.SSLError as e:
        ssl_stats['status'] = 'error'
        ssl_stats['error_message'] = f"SSL error: {e}"
    except ConnectionRefusedError as e: # More specific than socket.error for this case
        ssl_stats['status'] = 'error'
        ssl_stats['error_message'] = f"Connection refused: {e}"
    except socket.error as e: # General socket error
        ssl_stats['status'] = 'error'
        ssl_stats['error_message'] = f"Socket error: {e}"
    except Exception as e:
        ssl_stats['status'] = 'error'
        ssl_stats['error_message'] = f"Unexpected error during SSL/TLS analysis: {e}"

    if ssl_stats['status'] == 'error':
        print(f"{COLOR_RED}Error in SSL/TLS analysis for {target_host}:{port}: {ssl_stats['error_message']}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, f"SSL/TLS Analysis Error: {target_host}:{port}", ssl_stats['error_message'])
    
    # HSTS Header Check (only if initial connection was somewhat successful, i.e. cert was obtained or basic socket connection was possible)
    # For simplicity, we attempt this even if some cert validation warnings occurred, as HSTS is a separate HTTP-level check.
    # But if the very initial socket connection failed (e.g. timeout, refused), this won't run due to early return or error state.
    if ssl_stats['status'] != 'error' or "Connection timed out" not in str(ssl_stats['error_message']) and "Connection refused" not in str(ssl_stats['error_message']):
        try:
            # Use a new SSL context for HTTPSConnection for cleaner HSTS check
            hsts_context = ssl.create_default_context()
            conn_hsts = http.client.HTTPSConnection(target_host, port, timeout=5, context=hsts_context)
            conn_hsts.request('HEAD', '/')
            res = conn_hsts.getresponse()
            hsts_header = res.getheader('Strict-Transport-Security')
            ssl_stats['hsts_header'] = hsts_header
            if hsts_header:
                add_finding_func(managed_findings, SEVERITY_INFO, f"HSTS Header Found: {target_host}:{port}", f"Header: {hsts_header}")
            else:
                add_finding_func(managed_findings, SEVERITY_LOW, f"HSTS Header Missing: {target_host}:{port}", "The Strict-Transport-Security header was not found.", "Consider implementing HSTS to protect against protocol downgrade attacks and cookie hijacking.")
            conn_hsts.close()
        except Exception as e_hsts:
            # This is not a primary failure of cert analysis, but good to note.
            hsts_error_msg = f"Could not check HSTS header for {target_host}:{port}: {type(e_hsts).__name__} - {e_hsts}"
            print(f"{COLOR_YELLOW}Warning: {hsts_error_msg}{COLOR_RESET}")
            add_finding_func(managed_findings, SEVERITY_LOW, f"HSTS Check Error: {target_host}:{port}", hsts_error_msg)
            ssl_stats['hsts_header'] = f"Error checking: {type(e_hsts).__name__}"


    # Store stats
    if 'target_profiles' in managed_stats and target_host in managed_stats['target_profiles']:
        managed_stats['target_profiles'][target_host]['ssl_tls_analysis'] = ssl_stats
    else: # Fallback if profile_target didn't create the base structure (should not happen in normal flow)
        if 'target_profiles' not in managed_stats: managed_stats['target_profiles'] = {}
        if target_host not in managed_stats['target_profiles']: managed_stats['target_profiles'][target_host] = {}
        managed_stats['target_profiles'][target_host]['ssl_tls_analysis'] = ssl_stats
    
    print(f"{COLOR_GREEN}[+] SSL/TLS certificate analysis for {target_host}:{port} completed.{COLOR_RESET}")


if __name__ == '__main__':
    # Example Usage (requires a mock environment for managed_stats, managed_findings, add_finding_func)
    print("This module is intended to be run as part of the Guardian scanner.")
    
    # Mock objects for standalone testing (simplified)
    class MockManagerDict(dict):
        def __init__(self, *args, **kwargs): # Allow initialization like a normal dict
            super().__init__(*args, **kwargs)
            if 'target_profiles' not in self: # Ensure base key if accessed
                 self['target_profiles'] = MockManagerDict()

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
        SEVERITY_HIGH: MockManagerList(),
        SEVERITY_CRITICAL: MockManagerList(), # Added for hostname mismatch
        SEVERITY_LOW: MockManagerList() # Added for HSTS/date parsing errors
    }
    mock_stats_store = MockManagerDict()
    # Ensure 'target_profiles' and a specific target exist for ssl_tls_analysis to be added to
    test_target_main = "www.google.com" # Changed from 127.0.0.1 to a real SSL target for better testing
    #test_target_main = "expired.badssl.com"
    #test_target_main = "self-signed.badssl.com"
    #test_target_main = "wrong.host.badssl.com"
    
    mock_stats_store['target_profiles'][test_target_main] = MockManagerDict() # Ensure the target key exists

    def mock_add_finding(findings_dict, severity, title, description, recommendation="N/A"):
        print(f"  FINDING [{severity}]: {title} - {description} (Rec: {recommendation})")
        if severity in findings_dict: # Ensure severity key exists
            findings_dict[severity].append({'title': title, 'description': description, 'recommendation': recommendation})

    # --- Test target_profiler (main part) ---
    print(f"\n--- Running Mock Target Profiling for {test_target_main} ---")
    try:
        # We'll only call analyze_ssl_tls_certificate directly for this test,
        # as profile_target's modification is part of this subtask but tested via integration.
        # profile_target(mock_stats_store, mock_findings_store, mock_add_finding, test_target_main)
        
        # Direct call for testing analyze_ssl_tls_certificate
        print(f"\n--- Directly testing SSL/TLS analysis for {test_target_main}:443 ---")
        analyze_ssl_tls_certificate(mock_stats_store, mock_findings_store, mock_add_finding, test_target_main, port=443)

    except Exception as e:
        print(f"Error during mock target profiling/SSL analysis: {e}")
    
    print("\n--- Mock Stats for Target Profiler ---")
    if test_target_main in mock_stats_store['target_profiles']:
        profile_data = mock_stats_store['target_profiles'][test_target_main]
        
        # Print SSL/TLS analysis stats if available
        if 'ssl_tls_analysis' in profile_data:
            print(f"  SSL/TLS Analysis for {profile_data['ssl_tls_analysis'].get('target_host')}:{profile_data['ssl_tls_analysis'].get('port')}:")
            for key, value in profile_data['ssl_tls_analysis'].items():
                if key == 'certificate_details' and isinstance(value, dict):
                    print(f"    Certificate Details:")
                    for ck, cv in value.items():
                        if ck == 'subjectAltName':
                            print(f"      {ck}: {cv}") # Print SANs list
                        else:
                            print(f"      {ck}: {str(cv)[:100]}") # Truncate long values
                else:
                    print(f"    {key}: {value}")
        else:
            print(f"  No SSL/TLS analysis data found for {test_target_main}.")
            
        # Print other parts of profile_data if profile_target was run
        for key, value in profile_data.items():
            if key == 'ssl_tls_analysis': continue # Already handled
            if key == 'banners' and isinstance(value, dict):
                print(f"  Banners Found: {len(value)}")
                for port, banner in value.items():
                    print(f"    Port {port}: {banner[:60]}...") 
            elif key == 'open_ports' and isinstance(value, list):
                 print(f"  Open Ports: {value}")
            elif key not in ['ssl_tls_analysis']: # Avoid re-printing if other keys exist
                print(f"  {key}: {value}")
    else:
        print(f"  No profile data found for {test_target_main} in mock_stats_store.")


    print("\n--- Mock Findings from Target Profiler & SSL/TLS Analysis ---")
    for severity, findings_list in mock_findings_store.items():
        if findings_list._list:
            print(f"  {severity.upper()} Findings:")
            for finding in findings_list._list:
                print(f"    - {finding['title']}")
    
    print("\nNote: Standalone SSL/TLS test depends on live target and network conditions.")
