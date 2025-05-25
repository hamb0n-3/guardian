#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Module: MITM Detector (ARP Cache Analysis)
"""

import psutil
import platform
import re
import socket
import os # For resolv.conf parsing

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

from modules.utils import (
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_RESET,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    run_command
)

def detect_arp_cache_anomalies(managed_stats, managed_findings, add_finding_func):
    """
    Analyzes the ARP cache for anomalies, specifically focusing on the default gateway.
    """
    print(f"{COLOR_GREEN}[*] Analyzing ARP cache for anomalies...{COLOR_RESET}")

    # Initialize stats structure for this module
    # The main guardian.py wrapper should ensure managed_stats['mitm_detection'] is a manager.dict()
    if 'mitm_detection' not in managed_stats:
        # This is a fallback and might not be multiprocess-safe if not handled by caller
        managed_stats['mitm_detection'] = {} 
    
    arp_analysis_stats = {
        'default_gateway_ip': None,
        'gateway_mac_entries': [],
        'anomalies_found': 0,
        'status': 'completed',
        'error_message': None
    }

    # 1. Determine the Default Gateway IP
    default_gateway_ip = None
    try:
        gateways = psutil.net_if_gateways()
        # We are interested in the default gateway for AF_INET (IPv4)
        # gateways is a dict like: {2: [('192.168.1.1', 'en0', True)], 17: [('fe80::1', 'en0', True)]}
        # where 2 is AF_INET. The third element of the tuple indicates if it's a default route.
        if 2 in gateways: # AF_INET for IPv4
            for gw_info in gateways[2]:
                if gw_info[2]: # is_default flag
                    default_gateway_ip = gw_info[0]
                    break 
        
        if not default_gateway_ip:
            # Check for default routes without the is_default flag (less common, fallback)
             if 2 in gateways and gateways[2]:
                default_gateway_ip = gateways[2][0][0] # Pick first IPv4 gateway if no explicit default

    except Exception as e:
        error_msg = f"Error determining default gateway: {e}"
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_MEDIUM, "ARP Analysis Error", error_msg, "Could not determine default gateway via psutil.")
        arp_analysis_stats['status'] = 'error'
        arp_analysis_stats['error_message'] = error_msg
        managed_stats['mitm_detection']['arp_cache_analysis'] = arp_analysis_stats
        return

    if not default_gateway_ip:
        error_msg = "Could not determine default IPv4 gateway."
        add_finding_func(managed_findings, SEVERITY_MEDIUM, "ARP Analysis Error", error_msg, "Verify network configuration and default route.")
        arp_analysis_stats['status'] = 'error'
        arp_analysis_stats['error_message'] = error_msg
        managed_stats['mitm_detection']['arp_cache_analysis'] = arp_analysis_stats
        return

    arp_analysis_stats['default_gateway_ip'] = default_gateway_ip
    print(f"{COLOR_GREEN}[+] Default Gateway IP determined: {default_gateway_ip}{COLOR_RESET}")

    # 2. Read and Parse ARP Cache
    system = platform.system()
    arp_entries = []

    if system == "Windows":
        command = ["arp", "-a"]
        # Regex for Windows: "  192.168.1.1           00-1a-2b-3c-4d-5e     dynamic"
        # Need to handle interface lines like "Interface: 192.168.1.100 --- 0xb"
        # MAC can be xx-xx-xx-xx-xx-xx
        # We are interested in lines with IP and MAC.
        # Regex should capture IP and MAC.
        # Example: "  192.168.1.254         a0-b1-c2-d3-e4-f5     dynamic"
        #          "  224.0.0.22            01-00-5e-00-00-16     static" (multicast, ignore later if needed)
        arp_regex = re.compile(r"^\s*([\d\.]+)\s+([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}\s+\w+")

    else: # Linux/macOS
        command = ["arp", "-n"]
        # Regex for Linux/macOS: "192.168.1.1              ether   00:1a:2b:3c:4d:5e   C                     en0"
        #                        "? (192.168.1.1) at 00:1a:2b:3c:4d:5e [ether] on enp0s3" (common Linux)
        #                        "? (192.168.1.123) at <incomplete> on wlp2s0" (incomplete, ignore)
        # MAC can be xx:xx:xx:xx:xx:xx
        # We need to capture IP and MAC.
        # Regex for "IP_ADDRESS        ether   MAC_ADDRESS .*" (BSD style)
        # or "IP_ADDRESS dev INTERFACE lladdr MAC_ADDRESS ..." (Linux `ip neigh` style, though `arp -n` is more consistent for this)
        # `arp -n` on Linux often gives: "? (IP_ADDRESS) at MAC_ADDRESS [ether] on INTERFACE"
        arp_regex = re.compile(r"^(?:\?\s*\()([\d\.]+)\)?\s+at\s+([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|" # Linux `arp -n`
                               r"^([\d\.]+)\s+\w+\s+([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}") # BSD `arp -n`
                               # Simpler combined approach: look for IP then MAC
        arp_regex = re.compile(r"([\d\.]+)\s+.*?\s+([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")


    success, output = run_command(command, timeout=10)

    if not success or not output:
        error_msg = f"Failed to execute '{' '.join(command)}' or no output received."
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_MEDIUM, "ARP Analysis Error", error_msg, "Verify ARP command availability and permissions.")
        arp_analysis_stats['status'] = 'error'
        arp_analysis_stats['error_message'] = error_msg
        managed_stats['mitm_detection']['arp_cache_analysis'] = arp_analysis_stats
        return

    parsed_arp_entries = []
    for line in output.splitlines():
        line = line.strip()
        # Skip header lines or interface lines (Windows)
        if not line or (system == "Windows" and (line.lower().startswith("interface:") or line.lower().startswith("internet address"))):
            continue
        
        match = arp_regex.search(line)
        if match:
            # The regex will have one IP and one MAC group, but due to OR or multiple groups, need to pick correctly
            # For the simplified regex:
            ip_address = match.group(1)
            mac_address_full = match.group(2) + match.group(0).split()[-2][-2:] # this is messy due to how group(2) captures only the first part of MAC
            
            # Refined extraction based on the last simplified regex:
            # The simplified regex `([\d\.]+)\s+.*?\s+([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`
            # match.group(1) is IP. The MAC is the full match of the MAC part.
            # A bit of a hacky way to reconstruct the MAC if the regex is not perfect:
            mac_parts = re.findall(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
            if ip_address and mac_parts:
                mac_address = mac_parts[0] # Take the first full MAC found on the line
                # Normalize MAC address (e.g., to all uppercase with colons)
                mac_address = mac_address.upper().replace('-', ':')
                parsed_arp_entries.append({'ip': ip_address, 'mac': mac_address})

    if not parsed_arp_entries:
        error_msg = "ARP cache was read but no valid entries could be parsed."
        # This might be normal if the ARP cache is empty or only contains incomplete entries.
        # Consider severity based on whether output was present.
        print(f"{COLOR_YELLOW}Warning: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_LOW, "ARP Analysis Info", error_msg, "This might be normal on a quiet network or if regex needs adjustment for OS variant.")
        # Do not mark as error, proceed to check gateway presence based on empty list.
    
    arp_analysis_stats['parsed_entry_count'] = len(parsed_arp_entries)

    # 3. Analyze ARP Entries for Gateway Anomalies
    gateway_macs_found = set() # Use a set to store unique MACs for the gateway
    for entry in parsed_arp_entries:
        if entry['ip'] == default_gateway_ip:
            gateway_macs_found.add(entry['mac'])
            # Store all MACs associated with the gateway for stats, even if duplicate in cache (set handles uniqueness for anomaly)
            arp_analysis_stats['gateway_mac_entries'].append(entry['mac']) 

    if not gateway_macs_found:
        msg = f"No ARP entry found for default gateway ({default_gateway_ip})."
        add_finding_func(managed_findings, SEVERITY_MEDIUM, "Gateway ARP Entry Missing", msg,
                         "This could be normal if no recent traffic to gateway. If persistent, verify gateway reachability. Hinders ARP spoof detection.")
        arp_analysis_stats['status'] = 'warning' # Not a full error, but a notable state
        arp_analysis_stats['error_message'] = msg # Use error_message to store this warning too
    elif len(gateway_macs_found) > 1:
        arp_analysis_stats['anomalies_found'] += 1
        mac_list_str = ", ".join(sorted(list(gateway_macs_found)))
        critical_msg = f"Default gateway ({default_gateway_ip}) is associated with multiple MAC addresses: {mac_list_str}."
        add_finding_func(managed_findings, SEVERITY_CRITICAL, "Potential ARP Spoofing Detected", critical_msg,
                         "Investigate immediately. This could indicate an ARP spoofing attack. Verify the legitimate MAC address of your gateway and check for rogue devices.")
    else: # Exactly one MAC found
        mac_address = list(gateway_macs_found)[0]
        info_msg = f"Default gateway ({default_gateway_ip}) mapped to MAC: {mac_address}."
        add_finding_func(managed_findings, SEVERITY_INFO, "Gateway ARP Entry Consistent", info_msg)

    managed_stats['mitm_detection']['arp_cache_analysis'] = arp_analysis_stats
    print(f"{COLOR_GREEN}[+] ARP cache analysis completed.{COLOR_RESET}")

def detect_dns_spoofing(managed_stats, managed_findings, add_finding_func):
    """
    Detects potential DNS spoofing by comparing results from system DNS and public DNS servers.
    """
    print(f"{COLOR_GREEN}[*] Analyzing DNS for potential spoofing...{COLOR_RESET}")

    if not DNSPYTHON_AVAILABLE:
        error_msg = "DNSPython library not found. DNS Spoofing detection skipped."
        print(f"{COLOR_RED}Error: {error_msg}{COLOR_RESET}")
        add_finding_func(managed_findings, SEVERITY_HIGH, "DNS Spoofing Detection Error", error_msg,
                         "Please install dnspython (e.g., pip install dnspython) to enable this check.")
        # Initialize stats structure even if skipped
        if 'mitm_detection' not in managed_stats:
            managed_stats['mitm_detection'] = {}
        managed_stats['mitm_detection']['dns_spoofing'] = {
            'status': 'skipped',
            'error_message': error_msg,
            'checks': [],
            'anomalies_found': 0,
            'system_servers': []
        }
        return

    domains_to_test = ['www.google.com', 'www.example.com', 'www.wikipedia.org']
    public_dns_servers = ['8.8.8.8', '1.1.1.1'] # Google DNS, Cloudflare DNS
    
    dns_spoof_stats = {
        'checks': [], 
        'anomalies_found': 0, 
        'system_servers': [],
        'status': 'completed',
        'error_message': None
    }

    # Get System DNS Servers
    system_dns_servers = []
    system = platform.system()
    if system == "Linux" or system == "Darwin": # Darwin is macOS
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        parts = line.strip().split()
                        if len(parts) > 1:
                            system_dns_servers.append(parts[1])
        except FileNotFoundError:
            add_finding_func(managed_findings, SEVERITY_LOW, "DNS System Config", "/etc/resolv.conf not found.")
        except Exception as e:
            add_finding_func(managed_findings, SEVERITY_LOW, "DNS System Config Error", f"Error reading /etc/resolv.conf: {e}")
    elif system == "Windows":
        try:
            success, output = run_command(["ipconfig", "/all"], timeout=10)
            if success and output:
                # Regex to find DNS server lines, which may appear multiple times
                # Example: "   DNS Servers . . . . . . . . . . . : 192.168.1.1"
                #          "                                       1.1.1.1" (additional server on next line)
                # This regex is simplified and might need refinement for complex Windows setups.
                # It looks for lines starting with "DNS Servers" and captures the IP.
                # Then it looks for subsequent lines that are just IPs.
                dns_lines = re.findall(r"(?:DNS Servers[\s.:]*([\d\.]+)|^\s+([\d\.]+))", output, re.MULTILINE)
                for primary_dns, secondary_dns in dns_lines:
                    if primary_dns: # From "DNS Servers ..." line
                        system_dns_servers.append(primary_dns)
                    if secondary_dns: # From subsequent lines with just an IP
                        system_dns_servers.append(secondary_dns)
                # Remove duplicates if any from regex capture groups
                system_dns_servers = sorted(list(set(s for s in system_dns_servers if s))) # Filter out empty strings
            else:
                add_finding_func(managed_findings, SEVERITY_LOW, "DNS System Config", "Failed to run ipconfig /all or no output.")
        except Exception as e:
            add_finding_func(managed_findings, SEVERITY_LOW, "DNS System Config Error", f"Error running ipconfig /all: {e}")

    dns_spoof_stats['system_servers'] = system_dns_servers
    if not system_dns_servers:
        add_finding_func(managed_findings, SEVERITY_LOW, "DNS System Config", "No system DNS servers found/parsed. Comparison will rely on socket.gethostbyname_ex vs public DNS.")
    else:
        add_finding_func(managed_findings, SEVERITY_INFO, "System DNS Servers", f"Found system DNS servers: {', '.join(system_dns_servers)}")


    # Perform Lookups and Compare
    for domain in domains_to_test:
        domain_check_result = {'domain': domain, 'system_resolver_ips': [], 'public_resolver_ips': {}}
        system_ips_set = set()

        # System Resolver (using socket.gethostbyname_ex for default system resolution)
        try:
            _, _, system_ips_list = socket.gethostbyname_ex(domain)
            system_ips_set = set(system_ips_list)
            domain_check_result['system_resolver_ips'] = sorted(list(system_ips_set))
        except socket.gaierror as e:
            add_finding_func(managed_findings, SEVERITY_LOW, f"DNS Lookup Failed (System): {domain}", f"System resolver could not resolve {domain}: {e}")
        except Exception as e_sys: # Catch any other unexpected error during system resolution
            add_finding_func(managed_findings, SEVERITY_LOW, f"DNS Lookup Error (System): {domain}", f"Unexpected error for {domain} with system resolver: {e_sys}")


        # Public Resolvers
        for server_ip in public_dns_servers:
            public_ips_for_server_set = set()
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server_ip]
                resolver.timeout = 2.0
                resolver.lifetime = 2.0
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    public_ips_for_server_set.add(rdata.address)
                domain_check_result['public_resolver_ips'][server_ip] = sorted(list(public_ips_for_server_set))
            except dns.resolver.NXDOMAIN:
                add_finding_func(managed_findings, SEVERITY_LOW, f"DNS NXDOMAIN (Public: {server_ip}): {domain}", f"{domain} does not exist according to {server_ip}.")
                domain_check_result['public_resolver_ips'][server_ip] = ["NXDOMAIN"]
            except dns.resolver.Timeout:
                add_finding_func(managed_findings, SEVERITY_LOW, f"DNS Timeout (Public: {server_ip}): {domain}", f"Query to {server_ip} for {domain} timed out.")
                domain_check_result['public_resolver_ips'][server_ip] = ["Timeout"]
            except dns.exception.DNSException as e:
                add_finding_func(managed_findings, SEVERITY_LOW, f"DNS Error (Public: {server_ip}): {domain}", f"DNS query to {server_ip} for {domain} failed: {e}")
                domain_check_result['public_resolver_ips'][server_ip] = [f"Error: {type(e).__name__}"]


        # Comparison Logic
        if system_ips_set: # Only compare if system resolver returned something
            for public_server, public_ips_list in domain_check_result['public_resolver_ips'].items():
                # Ensure public_ips_list doesn't contain error strings like "NXDOMAIN" or "Timeout" before converting to set for comparison
                valid_public_ips_set = set(ip for ip in public_ips_list if not (ip in ["NXDOMAIN", "Timeout"] or ip.startswith("Error:")))
                
                if valid_public_ips_set and (system_ips_set != valid_public_ips_set):
                    dns_spoof_stats['anomalies_found'] += 1
                    msg = (f"Potential DNS Spoofing for {domain}: System resolver IPs ({', '.join(sorted(list(system_ips_set)))}) "
                           f"differ from {public_server} IPs ({', '.join(sorted(list(valid_public_ips_set)))}).")
                    rec = "Verify your network's DNS configuration and investigate potential local DNS manipulation or upstream DNS issues."
                    add_finding_func(managed_findings, SEVERITY_HIGH, "Potential DNS Spoofing Detected", msg, rec)
        
        dns_spoof_stats['checks'].append(domain_check_result)

    # Store final stats
    if 'mitm_detection' not in managed_stats: # Ensure base key exists
        managed_stats['mitm_detection'] = {}
    managed_stats['mitm_detection']['dns_spoofing'] = dns_spoof_stats
    
    summary_msg = f"DNS spoofing checks completed. Anomalies found: {dns_spoof_stats['anomalies_found']}."
    add_finding_func(managed_findings, SEVERITY_INFO, "DNS Spoofing Check Summary", summary_msg)
    print(f"{COLOR_GREEN}[+] {summary_msg}{COLOR_RESET}")


if __name__ == '__main__':
    print("This module is intended to be run as part of the Guardian scanner.")

    # Mock objects for standalone testing
    class MockManagerDict(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            if 'mitm_detection' not in self: # Ensure the nested structure expected by the module
                self['mitm_detection'] = MockManagerDict()

    class MockManagerList:
        def __init__(self): self._list = []
        def append(self, item): self._list.append(item)
        def __repr__(self): return repr(self._list)

    mock_findings_store = {
        SEVERITY_INFO: MockManagerList(), SEVERITY_LOW: MockManagerList(),
        SEVERITY_MEDIUM: MockManagerList(), SEVERITY_HIGH: MockManagerList(),
        SEVERITY_CRITICAL: MockManagerList()
    }
    mock_stats_store = MockManagerDict()
    # mock_stats_store['mitm_detection'] is auto-created by MockManagerDict if accessed.

    def mock_add_finding(findings_dict, severity, title, description, recommendation="N/A"):
        print(f"  FINDING [{severity}]: {title} - {description} (Rec: {recommendation})")
        if severity in findings_dict:
            findings_dict[severity].append({'title': title, 'description': description, 'recommendation': recommendation})

    print("\n--- Running Mock ARP Cache Anomaly Detection ---")
    try:
        detect_arp_cache_anomalies(mock_stats_store, mock_findings_store, mock_add_finding)
    except Exception as e:
        print(f"Error during mock ARP analysis: {e}")
    
    print("\n--- Running Mock DNS Spoofing Detection ---")
    try:
        detect_dns_spoofing(mock_stats_store, mock_findings_store, mock_add_finding)
    except Exception as e:
        print(f"Error during mock DNS Spoofing analysis: {e}")


    print("\n--- Mock Stats from MiTM Detection ---")
    mitm_stats = mock_stats_store.get('mitm_detection', {})
    if mitm_stats.get('arp_cache_analysis'):
        print("  ARP Cache Analysis Stats:")
        for key, value in mitm_stats['arp_cache_analysis'].items():
            print(f"    {key}: {value}")
    else:
        print("  No ARP analysis stats found.")
    
    if mitm_stats.get('dns_spoofing'):
        print("  DNS Spoofing Stats:")
        dns_stats_display = mitm_stats['dns_spoofing']
        print(f"    Status: {dns_stats_display.get('status')}")
        if dns_stats_display.get('error_message'):
             print(f"    Error Message: {dns_stats_display.get('error_message')}")
        print(f"    Anomalies Found: {dns_stats_display.get('anomalies_found')}")
        print(f"    System Servers: {dns_stats_display.get('system_servers')}")
        print(f"    Checks Performed: {len(dns_stats_display.get('checks', []))}")
        # Optionally print details of first check if needed for debugging
        # if dns_stats_display.get('checks'):
        #    print(f"      Example Check (www.google.com): {dns_stats_display['checks'][0]}")
    else:
        print("  No DNS Spoofing stats found.")


    print("\n--- Mock Findings from MiTM Detection ---")
    for severity, findings_list in mock_findings_store.items():
        if findings_list._list: # Check if list is not empty
            print(f"  {severity.upper()} Findings:")
            for finding in findings_list._list: # Iterate through actual items
                print(f"    - {finding['title']}")
    print("\nNote: Standalone test depends on live system configuration and network conditions.")
