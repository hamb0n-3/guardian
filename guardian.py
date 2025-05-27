#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Author: hamb0n-3

"""
Guardian: Network Security Scanner (Multiprocess Enabled)

This script orchestrates various network security modules to gather network
information, analyze it for potential security vulnerabilities and
misconfigurations, and provide actionable findings with a focus on
network security heuristics.
"""

import os
import json
from datetime import datetime
import multiprocessing
import time # For basic timing
import logging # Added for logging framework
import argparse # Added for command-line arguments

# Import constants and utility functions
from modules.utils import (
    COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE,
    COLOR_MAGENTA, COLOR_CYAN, COLOR_RESET, COLOR_BOLD,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
)

# Import scanning/analysis modules (will be called via wrappers)
from modules import network_scan
from modules import ssh_analysis
# Import newly added modules
from modules import log_analysis
from modules import local_traffic_analyzer
from modules import target_profiler
from modules import mitm_detector

# --- Process-Safe Finding Adder ---
def add_finding_mp(managed_findings, severity, title, description, recommendation="N/A"):
    """
    Adds a finding to the MANAGED findings dictionary (process-safe).
    Args:
        managed_findings (multiprocessing.Manager.dict): The shared findings dict.
        severity (str): Severity level.
        title (str): Finding title.
        description (str): Finding description.
        recommendation (str, optional): Recommendation.
    """
    # Obtain a logger instance for this function
    logger = logging.getLogger("guardian.finding_adder")
    try:
        # Manager list proxies support append directly.
        if severity not in managed_findings:
             # Use logger instead of print for this error
             logger.error(f"Invalid severity key '{severity}' used in add_finding_mp for: {title}")
             return
        managed_findings[severity].append({
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
         # Use logger instead of print for errors from subprocesses
         logger.error(f"[ERROR in add_finding_mp] {e} for finding: {title}")

# --- Module Wrapper Functions for Multiprocessing ---
# These wrappers call the actual module functions, passing managed dicts
# IMPORTANT: The actual module functions need to be updated to accept
# (managed_stats, managed_findings, add_finding_func, *original_args)

def run_network_scan_wrapper(managed_stats, managed_findings):
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_network_scan_wrapper.__name__}")
    module_name = "network_scan (interfaces & ports)"
    try:
        logger.info(f"Starting module: {module_name}")
        network_scan.get_network_interfaces(managed_stats, managed_findings, add_finding_mp)
        network_scan.get_listening_ports(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_ssh_analysis_wrapper(managed_stats, managed_findings):
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_ssh_analysis_wrapper.__name__}")
    module_name = ssh_analysis.check_ssh_config.__name__
    try:
        logger.info(f"Starting module: {module_name}")
        ssh_analysis.check_ssh_config(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

# --- Wrappers for NEW Modules ---

def run_log_analysis_wrapper(managed_stats, managed_findings):
    """Wrapper to run the log analysis module in a separate process."""
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_log_analysis_wrapper.__name__}")
    module_name = "log_analysis (auth.log)"
    try:
        logger.info(f"Starting module: {module_name}")
        # Call the primary function from the log_analysis module
        log_analysis.analyze_auth_log(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_local_traffic_analysis_wrapper(managed_stats, managed_findings):
    logger = logging.getLogger(f"guardian.{run_local_traffic_analysis_wrapper.__name__}")
    module_name = "local_traffic_analyzer"
    try:
        logger.info(f"Starting module: {module_name}")
        local_traffic_analyzer.analyze_local_traffic(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_traceroute_wrapper(managed_stats, managed_findings, target_host):
    """Wrapper to run the traceroute function from network_scan module."""
    logger = logging.getLogger(f"guardian.{run_traceroute_wrapper.__name__}")
    module_name = f"traceroute to {target_host}"
    try:
        logger.info(f"Starting module: {module_name}")
        # Preparation of managed_stats['network']['traceroute_results'] is handled in main() before process creation
        network_scan.trace_route_to_target(managed_stats, managed_findings, add_finding_mp, target_host)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_target_profiling_wrapper(managed_stats, managed_findings, target_host):
    """Wrapper to run the target profiling module."""
    logger = logging.getLogger(f"guardian.{run_target_profiling_wrapper.__name__}")
    module_name = f"target_profiler for {target_host}"
    try:
        logger.info(f"Starting module: {module_name}")
        # managed_stats['target_profiles'] should be initialized in main()
        target_profiler.profile_target(managed_stats, managed_findings, add_finding_mp, target_host)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_local_mitm_detection_wrapper(managed_stats, managed_findings):
    """Wrapper for local MiTM detection modules (ARP, Local Promiscuous Mode)."""
    logger = logging.getLogger(f"guardian.{run_local_mitm_detection_wrapper.__name__}")
    
    module_name_arp = "arp_cache_analysis"
    try:
        logger.info(f"Starting module: {module_name_arp}")
        mitm_detector.detect_arp_cache_anomalies(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name_arp}")
    except Exception as e:
        logger.error(f"Process Error in {module_name_arp}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name_arp}", f"Failed to run: {e}")

    module_name_local_promisc = "local_promiscuous_mode_detection"
    try:
        logger.info(f"Starting module: {module_name_local_promisc}")
        mitm_detector.detect_local_promiscuous_mode(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name_local_promisc}")
    except Exception as e:
        logger.error(f"Process Error in {module_name_local_promisc}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name_local_promisc}", f"Failed to run: {e}")

def run_dns_spoofing_detection_wrapper(managed_stats, managed_findings):
    """Wrapper to run the DNS Spoofing detection module."""
    logger = logging.getLogger(f"guardian.{run_dns_spoofing_detection_wrapper.__name__}")
    module_name = "dns_spoofing_detection"
    try:
        logger.info(f"Starting module: {module_name}")
        # managed_stats['mitm_detection'] is initialized in main()
        mitm_detector.detect_dns_spoofing(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_remote_promiscuous_detection_wrapper(managed_stats, managed_findings, target_host):
    """Wrapper for experimental remote promiscuous mode detection."""
    logger = logging.getLogger(f"guardian.{run_remote_promiscuous_detection_wrapper.__name__}")
    module_name = f"remote_promiscuous_mode_detection for {target_host}"
    try:
        logger.info(f"Starting module: {module_name} (Experimental)")
        # managed_stats['mitm_detection']['remote_promiscuous_mode'] is initialized in main()
        mitm_detector.detect_remote_promiscuous_mode(managed_stats, managed_findings, add_finding_mp, target_host)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_traceroute_analysis_wrapper(managed_stats, managed_findings):
    """Wrapper to run the traceroute analysis module in a separate process."""
    logger = logging.getLogger(f"guardian.{run_traceroute_analysis_wrapper.__name__}")
    module_name = "network_scan (traceroute)"
    # Define default target(s) for traceroute. Could be made configurable later.
    # For now, using a common public DNS server.
    default_target = "8.8.8.8" 
    try:
        logger.info(f"Starting module: {module_name} for target {default_target}")
        # network_scan.perform_traceroute was designed to be called directly
        network_scan.perform_traceroute(managed_stats, managed_findings, add_finding_mp, default_target)
        logger.info(f"Finished module: {module_name} for target {default_target}")
    except Exception as e:
        logger.error(f"Process Error in {module_name} for target {default_target}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name} ({default_target})", f"Failed to run: {e}")

# --- Helper Functions (Output Formatting) ---

def print_banner():
    """Prints a cool banner for the script."""
    print(f"{COLOR_CYAN}{COLOR_BOLD}")
    print("#############################################")
    print("#        Guardian Network Scanner         #") # Updated Banner
    print("#          Network Security Focus         #") # Updated Banner
    print("#############################################")
    print(f"{COLOR_RESET}")

def print_finding(severity, title, description, recommendation="N/A"):
    """Helper to print a single finding with appropriate color."""
    color_map = {
        SEVERITY_CRITICAL: COLOR_RED,
        SEVERITY_HIGH: COLOR_MAGENTA,
        SEVERITY_MEDIUM: COLOR_YELLOW,
        SEVERITY_LOW: COLOR_BLUE,
        SEVERITY_INFO: COLOR_CYAN
    }
    color = color_map.get(severity, COLOR_YELLOW)
    print(f"{color}{COLOR_BOLD}[{severity}]{COLOR_RESET} {COLOR_BOLD}{title}{COLOR_RESET}")
    print(f"  Desc: {description}")
    if recommendation != "N/A":
        print(f"  Rec:  {recommendation}")
    print("-" * 60)

def display_summary(final_findings, final_statistics):
    """Displays a summary of findings and statistics from managed dicts,
    with interactive drill-down for detailed findings."""
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}--- Scan Summary ---{COLOR_RESET}")

    # Findings Summary
    print(f"{COLOR_YELLOW}{COLOR_BOLD}Findings by Severity:{COLOR_RESET}")
    total_findings = sum(len(list(v)) for v in final_findings.values())
    if total_findings == 0:
        print(f"  {COLOR_GREEN}No significant security findings reported.{COLOR_RESET}")
    else:
        severity_order_for_summary = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
        for severity in severity_order_for_summary:
            count = len(list(final_findings.get(severity, [])))
            if count > 0:
                color_map = {
                    SEVERITY_CRITICAL: COLOR_RED,
                    SEVERITY_HIGH: COLOR_MAGENTA,
                    SEVERITY_MEDIUM: COLOR_YELLOW,
                    SEVERITY_LOW: COLOR_BLUE,
                    SEVERITY_INFO: COLOR_CYAN
                }
                color = color_map.get(severity, COLOR_YELLOW)
                print(f"  {color}{severity:<10}: {count}{COLOR_RESET}")

    # Key Statistics Summary - Access the managed dict
    print(f"\n{COLOR_YELLOW}{COLOR_BOLD}Key Statistics Gathered:{COLOR_RESET}")
    stats_printed = False
    # Convert managed dict proxy for reliable access
    stats_copy = dict(final_statistics)
    stats_printed = False # Initialize stats_printed

    if 'network' in stats_copy:
        net_stats = stats_copy['network']
        if 'interfaces' in net_stats:
            # interfaces value might be a managed dict, convert keys for display if needed
            print(f"  Network Interfaces: {len(net_stats.get('interfaces', {}))} found")
        if 'listening_ports_count' in net_stats:
            print(f"  Listening Ports: {net_stats.get('listening_ports_count', 0)} found")
        stats_printed = True
        
    if 'processes' in stats_copy:
        proc_stats = stats_copy['processes']
        process_list = proc_stats.get('list', [])
        print(f"  Running Processes: {proc_stats.get('count', 0)} found")

        # Summarize network activity and I/O from processes
        procs_with_net_connections = 0
        total_bytes_sent = 0
        total_bytes_read = 0
        for proc_data in process_list:
            if proc_data.get('network_connections') and len(proc_data['network_connections']) > 0:
                procs_with_net_connections += 1
            if isinstance(proc_data.get('bytes_sent'), int) and proc_data.get('bytes_sent') > 0:
                total_bytes_sent += proc_data['bytes_sent']
            if isinstance(proc_data.get('bytes_read'), int) and proc_data.get('bytes_read') > 0:
                total_bytes_read += proc_data['bytes_read']
        
        if procs_with_net_connections > 0:
            print(f"    Processes with Network Connections: {procs_with_net_connections}")
        
        if total_bytes_sent > 0 or total_bytes_read > 0:
            # Simple MB conversion for summary
            total_mb_sent = total_bytes_sent / (1024 * 1024)
            total_mb_read = total_bytes_read / (1024 * 1024)
            print(f"    Total Process I/O: {total_mb_sent:.2f} MB Written / {total_mb_read:.2f} MB Read (approx.)")
        stats_printed = True

    if 'users' in stats_copy:
        user_stats = stats_copy['users']
        # Access list proxies safely
        print(f"  User Accounts (/etc/passwd): {len(list(user_stats.get('accounts', [])))}")
        sudo_rules_count = len(list(user_stats.get('sudo_rules', [])))
        if sudo_rules_count > 0:
             print(f"  Potentially Risky Sudo Rules: {sudo_rules_count} flagged")
        stats_printed = True

    if 'ssh_config' in stats_copy:
        ssh_stats = stats_copy['ssh_config']
        if ssh_stats.get('exists'):
             print(f"  SSH Config: Analyzed {ssh_stats.get('path', 'N/A')}")
             stats_printed = True

    if 'logs' in stats_copy:
        log_stats = stats_copy['logs']
        auth_stats = log_stats.get('auth_log', {}) # Safely get sub-dict
        if auth_stats: # Check if auth_log stats exist
             analyzed_path = auth_stats.get('analyzed_path', '/var/log/auth.log')
             lines = auth_stats.get('lines_processed', 0)
             failed_logins = len(list(auth_stats.get('failed_logins', [])))
             # sudo_events related to log_analysis can remain if relevant to network context (e.g. remote sudo)
             sudo_events = len(list(auth_stats.get('sudo_events', []))) # Keep if network relevant
             ssh_logins = len(list(auth_stats.get('ssh_logins', [])))
             print(f"  Log Analysis ({os.path.basename(analyzed_path)}): {lines} lines processed")
             if failed_logins > 0: print(f"    Failed Logins Found: {failed_logins}")
             if sudo_events > 0: print(f"    Sudo Events (from logs): {sudo_events}") # Clarify origin
             if ssh_logins > 0: print(f"    SSH Logins Found: {ssh_logins}")
             stats_printed = True

    if 'local_traffic' in stats_copy:
        lt_stats = stats_copy['local_traffic']
        print(f"  Active Connections: {lt_stats.get('active_connections_count', 0)} (TCP: {lt_stats.get('tcp_connections', 0)}, UDP: {lt_stats.get('udp_connections', 0)})")
        stats_printed = True
    
    if 'network' in stats_copy and 'traceroute_results' in stats_copy['network']:
        traceroute_data = stats_copy['network']['traceroute_results']
        if traceroute_data: # Check if not empty
            print(f"\n{COLOR_YELLOW}{COLOR_BOLD}Traceroute Results:{COLOR_RESET}")
            for target, hops_list_or_error in traceroute_data.items():
                print(f"  {COLOR_CYAN}Target: {target}{COLOR_RESET}")
                if isinstance(hops_list_or_error, list) and hops_list_or_error:
                    if 'error' in hops_list_or_error[0]: # Check if the first item is an error dict
                        print(f"    {COLOR_RED}Error: {hops_list_or_error[0]['error']}{COLOR_RESET}")
                    else:
                        for hop_info in hops_list_or_error:
                            hop_num = hop_info.get('hop', 'N/A')
                            ip_addr = hop_info.get('ip', 'N/A')
                            hostname = hop_info.get('hostname', 'N/A')
                            avg_rtt = hop_info.get('avg_rtt', float('inf')) # Default to inf for N/A case
                            min_rtt = hop_info.get('min_rtt', float('inf'))
                            max_rtt = hop_info.get('max_rtt', float('inf'))
                            packet_loss = hop_info.get('packet_loss', 100.0) # Default to 100% loss

                            # Prepare RTT display string
                            if avg_rtt == float('inf') and min_rtt == float('inf') and max_rtt == float('inf'):
                                rtt_display = "N/A"
                            else:
                                rtt_display = f"{min_rtt:.2f}/{avg_rtt:.2f}/{max_rtt:.2f}ms"
                            
                            loss_display = f"{packet_loss:.0f}%"
                            if packet_loss == 100.0 and ip_addr == "Timeout":
                                loss_display += " (Timeout)"

                            line_color = COLOR_RESET
                            if packet_loss > 50: # High loss
                                line_color = COLOR_RED
                            elif packet_loss > 10: # Moderate loss
                                line_color = COLOR_YELLOW
                            elif avg_rtt > 200 and avg_rtt != float('inf'): # High RTT
                                line_color = COLOR_YELLOW
                            
                            print(f"{line_color}    Hop {hop_num:>2}: {ip_addr:<15} ({hostname if hostname != ip_addr else 'No RevDNS'}) "
                                  f"- RTT(min/avg/max): {rtt_display:<20} Loss: {loss_display}{COLOR_RESET}")
                else:
                    print(f"    No hops found or traceroute failed for {target}.")
            stats_printed = True

    if 'target_profiles' in stats_copy:
        profile_data = stats_copy['target_profiles']
        if profile_data: # Check if not empty
            print(f"\n{COLOR_YELLOW}{COLOR_BOLD}Target Profile Results:{COLOR_RESET}")
            for target, profile in profile_data.items():
                print(f"  {COLOR_CYAN}Target: {target}{COLOR_RESET}")
                # Check for 'status' and 'error_message' which are now part of target_profile_stats
                if profile.get('status') == 'error' and profile.get('error_message'):
                    print(f"    {COLOR_RED}Error: {profile['error_message']}{COLOR_RESET}")
                    continue
                # Check for general errors array if status isn't error (e.g. port specific errors)
                if 'errors' in profile and profile['errors']:
                     for err_entry in profile['errors'][:3]: # Show first 3 port errors
                         port_err_key = list(err_entry.keys())[0] # Port number or specific error key
                         port_err_val = err_entry[port_err_key]
                         print(f"    {COLOR_YELLOW}Port {port_err_key} Warning: {str(port_err_val)[:100]}{COLOR_RESET}")

                open_ports = profile.get('open_ports', [])
                if open_ports:
                    print(f"    {COLOR_GREEN}Open Ports:{COLOR_RESET} {', '.join(map(str, sorted(open_ports)))}")
                    banners = profile.get('banners', {})
                    if banners:
                        print(f"    {COLOR_GREEN}Banners:{COLOR_RESET}")
                        for port, banner in banners.items():
                            banner_preview = banner.strip().replace('\n', ' ').replace('\r', '')[:100] # Clean and shorten
                            print(f"      Port {port}: {banner_preview}...")
                elif not (profile.get('status') == 'error'): # If no open ports and not an error state already printed
                    print(f"    No common ports found open or target unresponsive.")

                # Display SSL/TLS Analysis Results
                ssl_analysis_results = profile.get('ssl_tls_analysis')
                if ssl_analysis_results:
                    print(f"    {COLOR_BLUE}SSL/TLS Analysis (Port {ssl_analysis_results.get('port', 'N/A')}):{COLOR_RESET}")
                    if ssl_analysis_results.get('status') == 'error':
                        print(f"      {COLOR_RED}Error: {ssl_analysis_results.get('error_message', 'Unknown SSL/TLS analysis error')}{COLOR_RESET}")
                    else:
                        # Hostname Verification
                        hostname_match = ssl_analysis_results.get('hostname_match')
                        if hostname_match is True:
                            print(f"      Hostname Verification: {COLOR_GREEN}Matched{COLOR_RESET}")
                        elif hostname_match is False:
                            print(f"      Hostname Verification: {COLOR_RED}MISMATCH!{COLOR_RESET}")
                        else:
                            print(f"      Hostname Verification: {COLOR_YELLOW}Unknown/Not Performed{COLOR_RESET}")

                        # Certificate Details
                        cert_details = ssl_analysis_results.get('certificate_details', {})
                        subject_cn = cert_details.get('subject_cn', 'N/A')
                        issuer_cn = cert_details.get('issuer_cn', 'N/A')
                        not_before = cert_details.get('notBefore', 'N/A')
                        not_after = cert_details.get('notAfter', 'N/A')
                        print(f"      Subject CN: {subject_cn}")
                        print(f"      Issuer CN: {issuer_cn}")
                        print(f"      Validity: From {not_before} to {not_after}")

                        # HSTS Header
                        hsts_header = ssl_analysis_results.get('hsts_header')
                        if hsts_header and not hsts_header.startswith("Error checking"):
                            print(f"      HSTS Header: Present ({hsts_header})")
                        elif hsts_header and hsts_header.startswith("Error checking"):
                             print(f"      HSTS Header: {COLOR_YELLOW}{hsts_header}{COLOR_RESET}")
                        else:
                            print(f"      HSTS Header: {COLOR_YELLOW}Not Found{COLOR_RESET}")
                        
                        # Specific Warnings from the module
                        ssl_warnings = ssl_analysis_results.get('warnings', [])
                        if ssl_warnings:
                            print(f"      {COLOR_YELLOW}Warnings:{COLOR_RESET}")
                            for warning in ssl_warnings:
                                print(f"        - {warning}")
            stats_printed = True

    if 'mitm_detection' in stats_copy and 'arp_cache_analysis' in stats_copy['mitm_detection']:
        arp_stats = stats_copy['mitm_detection']['arp_cache_analysis']
        # Ensure arp_stats is not None and default_gateway_ip key exists, providing 'N/A' if not.
        gateway_ip_display = arp_stats.get('default_gateway_ip', 'N/A') if arp_stats else 'N/A'
        print(f"\n{COLOR_YELLOW}{COLOR_BOLD}ARP Cache Analysis (Gateway: {gateway_ip_display}):{COLOR_RESET}")
        
        if arp_stats: # Proceed only if arp_stats itself is not None
            gateway_macs = arp_stats.get('gateway_mac_entries', [])
            # Check for a specific error message related to gateway detection or ARP processing first
            if arp_stats.get('status') == 'error' and arp_stats.get('error_message'):
                 print(f"  {COLOR_RED}Error: {arp_stats.get('error_message')}{COLOR_RESET}")
            elif arp_stats.get('status') == 'warning' and arp_stats.get('error_message'): # For "Gateway ARP Entry Missing"
                 print(f"  {COLOR_YELLOW}Warning: {arp_stats.get('error_message')}{COLOR_RESET}")
            elif arp_stats.get('anomalies_found', 0) > 0:
                # The finding already provides details, this is a summary
                print(f"  {COLOR_RED}Alert: Potential ARP spoofing! Gateway ({gateway_ip_display}) associated with multiple MACs: {', '.join(sorted(list(set(gateway_macs))))}{COLOR_RESET}")
            elif gateway_macs: # Normal case, one or more identical MACs for the gateway
                print(f"  Gateway MAC(s): {', '.join(sorted(list(set(gateway_macs))))}")
            elif not gateway_macs and arp_stats.get('default_gateway_ip'): # Gateway IP known, but no MACs found and no specific error/warning message shown above.
                 print(f"  No ARP entry currently found for the gateway ({gateway_ip_display}). This might be temporary.")
            # If arp_stats.get('default_gateway_ip') was None, it's handled by gateway_ip_display = 'N/A'
            # and the error message about not finding gateway would be more relevant.
        else: # arp_stats is None or empty dictionary
            print(f"  {COLOR_YELLOW}ARP analysis data is missing or incomplete.{COLOR_RESET}")
        stats_printed = True
    
    if 'network' in stats_copy and 'traceroute' in stats_copy['network']:
        traceroute_stats = stats_copy['network']['traceroute']
        print(f"\n  {COLOR_BLUE}{COLOR_BOLD}Traceroute Analysis:{COLOR_RESET}")
        if not traceroute_stats:
            print(f"    {COLOR_YELLOW}No traceroute data collected.{COLOR_RESET}")
        else:
            for target, trace_data in traceroute_stats.items():
                print(f"    Target: {COLOR_CYAN}{target}{COLOR_RESET}")
                if trace_data.get('error'):
                    print(f"      Status: {COLOR_RED}Error - {trace_data['error']}{COLOR_RESET}")
                elif not trace_data.get('hops'):
                    summary_msg = trace_data.get('summary', "No hops recorded and no specific error.")
                    print(f"      Status: {COLOR_YELLOW}{summary_msg}{COLOR_RESET}")
                else:
                    hops = trace_data['hops']
                    summary_msg = trace_data.get('summary', f"Trace completed with {len(hops)} hops.")
                    print(f"      Status: {COLOR_GREEN}{summary_msg}{COLOR_RESET}")
                    
                    rtts = [h['rtt_ms'] for h in hops if h['rtt_ms'] is not None]
                    avg_rtt = sum(rtts) / len(rtts) if rtts else 0
                    max_rtt = max(rtts) if rtts else 0
                    
                    notable_hops_issues = []
                    for hop in hops:
                        if hop['rtt_ms'] and hop['rtt_ms'] > 200: # High RTT
                            notable_hops_issues.append(f"Hop {hop['hop']} ({hop['ip']}): High RTT {hop['rtt_ms']:.2f}ms")
                        elif hop['packet_loss_percent'] == 100.0 and hop['ip'] != "N/A (Timeout)": # Explicit loss not just timeout
                             notable_hops_issues.append(f"Hop {hop['hop']} ({hop['ip']}): Packet Loss")
                        elif hop['ip'] == "N/A (Timeout)":
                             notable_hops_issues.append(f"Hop {hop['hop']}: Timeout")
                    
                    print(f"      Hops: {len(hops)}, Avg RTT: {avg_rtt:.2f}ms, Max RTT: {max_rtt:.2f}ms")
                    if notable_hops_issues:
                        print(f"      Notable Issues ({len(notable_hops_issues)}):")
                        for issue in notable_hops_issues[:3]: # Print first 3 notable issues
                            print(f"        - {issue}")
                        if len(notable_hops_issues) > 3:
                            print(f"        ... and {len(notable_hops_issues) - 3} more.")
                stats_printed = True
        print("-" * 40) # Separator for traceroute section
    # --- End NEW Module Statistics ---

    if 'mitm_detection' in stats_copy and 'dns_spoofing' in stats_copy['mitm_detection']:
        dns_stats = stats_copy['mitm_detection']['dns_spoofing']
        print(f"\n{COLOR_YELLOW}{COLOR_BOLD}DNS Spoofing Analysis:{COLOR_RESET}")
        if dns_stats.get('status') == 'skipped' and dns_stats.get('error_message'): # Check for skipped status
            print(f"  {COLOR_YELLOW}Skipped: {dns_stats['error_message']}{COLOR_RESET}")
        elif dns_stats.get('error_message'): # General errors during execution
            print(f"  {COLOR_RED}Error: {dns_stats['error_message']}{COLOR_RESET}")
        else:
            system_servers = dns_stats.get('system_servers', [])
            if system_servers:
                print(f"  System DNS Servers Found: {', '.join(system_servers)}")
            else:
                # This case might be covered by a finding from the module itself if /etc/resolv.conf was unreadable etc.
                # Or if system resolver is used without explicit servers.
                print(f"  {COLOR_YELLOW}Note: System DNS servers list might be empty if relying on implicit system resolver or parsing failed.{COLOR_RESET}")

            if dns_stats.get('anomalies_found', 0) > 0:
                print(f"  {COLOR_RED}Alert: Potential DNS spoofing anomalies detected! Review findings for details on specific domains.{COLOR_RESET}")
            
            # Optional: Detailed checks summary (already in findings)
            # total_domains_checked = len(dns_stats.get('checks', []))
            # print(f"  Domains Checked: {total_domains_checked}")
            
            if dns_stats.get('anomalies_found', 0) == 0 and not dns_stats.get('error_message') and dns_stats.get('status') != 'skipped':
                 print(f"  {COLOR_GREEN}No direct DNS resolution discrepancies found for tested domains against public resolvers.{COLOR_RESET}")
        stats_printed = True

    if 'mitm_detection' in stats_copy and 'local_promiscuous_mode' in stats_copy['mitm_detection']:
        local_promisc_stats = stats_copy['mitm_detection']['local_promiscuous_mode']
        print(f"\n{COLOR_YELLOW}{COLOR_BOLD}Local Promiscuous Mode Detection:{COLOR_RESET}")
        if local_promisc_stats.get('status') != 'completed' and local_promisc_stats.get('error_message'): # Show error/warning if not completed okay
            print(f"  {COLOR_YELLOW}Status: {local_promisc_stats.get('status')}. {local_promisc_stats.get('error_message', '')}{COLOR_RESET}")
        
        promisc_interfaces = local_promisc_stats.get('promiscuous_interfaces', [])
        if promisc_interfaces:
            print(f"  {COLOR_RED}Alert: Found local interface(s) in promiscuous mode: {', '.join(promisc_interfaces)}{COLOR_RESET}")
        # Only print "No local interfaces..." if status was 'completed' and no error message related to status is already shown.
        elif local_promisc_stats.get('status') == 'completed':
            print(f"  {COLOR_GREEN}No local interfaces detected in promiscuous mode.{COLOR_RESET}")
        
        print(f"  Interfaces Checked: {local_promisc_stats.get('interfaces_checked', 0)}")
        # If status was 'limited_support' (Windows) and no specific error, the generic error_message is the note.
        if local_promisc_stats.get('status') == 'limited_support' and not promisc_interfaces :
            print(f"  {COLOR_YELLOW}Note: {local_promisc_stats.get('error_message')}{COLOR_RESET}")

        stats_printed = True

    if 'mitm_detection' in stats_copy and 'remote_promiscuous_mode' in stats_copy['mitm_detection']:
        remote_promisc_all_targets = stats_copy['mitm_detection']['remote_promiscuous_mode']
        if remote_promisc_all_targets: # Check if not empty
            print(f"\n{COLOR_YELLOW}{COLOR_BOLD}Remote Promiscuous Mode Detection (Experimental):{COLOR_RESET}")
            for target_ip, data in remote_promisc_all_targets.items():
                print(f"  {COLOR_CYAN}Target: {target_ip}{COLOR_RESET}")
                if data.get('status') == 'skipped':
                    print(f"    {COLOR_YELLOW}Status: Skipped ({data.get('error_message', 'Scapy not available')}){COLOR_RESET}")
                elif data.get('status') == 'error':
                    print(f"    {COLOR_RED}Error: {data.get('error_message', 'Unknown error')}{COLOR_RESET}")
                elif data.get('response_to_bogus_mac_ping'):
                    print(f"    {COLOR_RED}Alert: Potential promiscuous mode - responded to ICMP ping with bogus MAC.{COLOR_RESET}")
                else:
                    print(f"    {COLOR_GREEN}No promiscuous mode indicators from ICMP test (or target did not respond).{COLOR_RESET}")
            stats_printed = True
    # Removed 'services' and 'environment' sections from summary as per refactoring goal

    if not stats_printed:
        print(f"  {COLOR_YELLOW}No network-related statistics gathered or modules run.{COLOR_RESET}")

    # --- Interactive Detailed Findings ---
    # The process list with connection/traffic details will be in the JSON.
    # For console summary, high-level process stats are already printed.
    # Specific process details could be shown if a finding related to that process is selected.
    
    if total_findings > 0:
        print(f"\n{COLOR_CYAN}{COLOR_BOLD}--- Detailed Findings ---{COLOR_RESET}")
        
        severity_map = { # Ensure this map is comprehensive for user input
            'C': SEVERITY_CRITICAL,
            'H': SEVERITY_HIGH,
            'M': SEVERITY_MEDIUM,
            'L': SEVERITY_LOW,
            'I': SEVERITY_INFO,
            'A': 'ALL', # For 'All' option
            'Q': 'QUIT', # For 'Quit' option
            'N': 'QUIT'  # For 'No' as a quit option
        }
        severity_display_order_all = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]

        while True:
            # Loop for interactive severity selection
            while True:
                prompt_message = (
                    f"\nSelect severities to view (e.g., C,H or M), or:\n"
                    f"  (C)ritical, (H)igh, (M)edium, (L)ow, (I)nfo\n"
                    f"  (A)ll findings, (Q)uit detailed view: "
                )
                user_input_raw = ""
                try:
                    user_input_raw = input(f"{COLOR_YELLOW}{prompt_message}{COLOR_RESET}").strip().upper()
                except EOFError:
                    logger.warning("EOFError received, likely non-interactive environment. Skipping detailed findings.")
                    print(f"\n  {COLOR_YELLOW}Skipping interactive detailed findings (non-interactive environment). Full report in JSON.{COLOR_RESET}")
                    return # Exit display_summary
                except Exception as e:
                    logger.error(f"Error during input for detailed findings: {e}")
                    print(f"\n  {COLOR_RED}Error during input. Skipping detailed findings. Full report in JSON.{COLOR_RESET}")
                    return # Exit display_summary

                if not user_input_raw:
                    print(f"  {COLOR_YELLOW}No selection. Please enter a valid option or Q to quit.{COLOR_RESET}")
                    continue

                selected_options = [opt.strip() for opt in user_input_raw.split(',')]
                
                # Check for Quit or All as standalone first
                if 'Q' in selected_options or 'N' in selected_options : # 'N' also for "No more"
                    print(f"  {COLOR_GREEN}Exiting detailed findings view.{COLOR_RESET}")
                    return # Exit display_summary
                
                if 'A' in selected_options:
                    print(f"  {COLOR_GREEN}Displaying all findings:{COLOR_RESET}")
                    any_displayed = False
                    for severity_level in severity_display_order_all:
                        findings_list = final_findings.get(severity_level, [])
                        if findings_list:
                            print(f"  {COLOR_CYAN}--- Findings for {severity_level} ({len(findings_list)}) ---{COLOR_RESET}")
                            for finding in findings_list:
                                print_finding(severity_level, finding['title'], finding['description'], finding.get('recommendation', 'N/A'))
                                # Here you could add process details if finding is process-related
                                # For example: if "PID:" in finding['description']: display_process_details_for_finding(final_stats, finding)
                            any_displayed = True
                    if not any_displayed:
                        print(f"  {COLOR_GREEN}No findings were reported across all severities.{COLOR_RESET}")
                    # 'A' implies showing all and then finishing this interactive section.
                    return # Exit display_summary

                # Process individual severity codes
                displayed_this_round = False
                for code in selected_options:
                    mapped_severity = severity_map.get(code)
                    if mapped_severity and mapped_severity not in ['ALL', 'QUIT']:
                        findings_list = final_findings.get(mapped_severity, [])
                        if findings_list:
                            print(f"  {COLOR_CYAN}--- Findings for {mapped_severity} ({len(findings_list)}) ---{COLOR_RESET}")
                            for finding in findings_list:
                                print_finding(mapped_severity, finding['title'], finding['description'], finding.get('recommendation', 'N/A'))
                            displayed_this_round = True
                        else:
                            print(f"  {COLOR_YELLOW}No findings for severity '{code}' ({mapped_severity}).{COLOR_RESET}")
                            displayed_this_round = True # Valid code, just no findings
                    elif not mapped_severity: # Unknown code
                        print(f"  {COLOR_RED}Unknown severity code '{code}'. Ignored.{COLOR_RESET}")
                
                if not displayed_this_round and selected_options: # If input was given but nothing valid was processed
                    print(f"  {COLOR_YELLOW}No valid severity codes entered for display. Try C, H, M, L, I, A, or Q.{COLOR_RESET}")
                # Loop continues for more selections

    # This part is reached if total_findings == 0 OR if the user quits the interactive loop
    elif total_findings == 0:
        # Already handled by the "No significant security findings reported" message earlier
        pass
    # Implicit else: if user quit, the "Exiting detailed findings view" message was already printed.


# --- Logging Setup Function ---
def setup_logging(log_level_str="INFO", log_file=None):
    """
    Configures the root logger for the application.
    This setup will be inherited by loggers obtained in other modules/parts of the script.
    Args:
        log_level_str (str): The desired logging level as a string (e.g., "DEBUG", "INFO").
        log_file (str, optional): Path to a file for logging. If None, logs only to console.
    """
    numeric_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_level, int):
        # Fallback to INFO if an invalid string is provided, and log a warning.
        # This print is used because logger might not be configured yet.
        print(f"{COLOR_YELLOW}Warning: Invalid log level '{log_level_str}'. Defaulting to INFO.{COLOR_RESET}")
        numeric_level = logging.INFO
        log_level_str = "INFO" # Update for consistency in messages

    # Define a standard log format. This format is chosen for clarity in log files
    # and console output for operational messages.
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(processName)s - %(message)s'
    
    # Configure the root logger.
    # We remove any existing handlers from the root logger to ensure our configuration
    # takes precedence and avoids duplicate log messages if the script is run multiple times
    # in an environment where handlers might persist (e.g., some interactive sessions).
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        handler.close() # Ensure handlers are closed before removal

    # BasicConfig sets up a StreamHandler (console) by default.
    logging.basicConfig(level=numeric_level, format=log_format)
    
    # If a log file path is provided, add a FileHandler to the root logger.
    # This means logs will go to both the console (from basicConfig) and the specified file.
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='a') # 'a' for append
            file_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(file_handler) # Add handler to the root logger
            # Initial log message to confirm file logging is active
            logging.info(f"Logging to file: {log_file} at level: {log_level_str.upper()}")
        except Exception as e:
            # If file handler setup fails, log an error to the console (which should be working).
            logging.error(f"Failed to set up log file handler for {log_file}: {e}")
            print(f"{COLOR_RED}Error: Could not open log file {log_file}. Check permissions and path.{COLOR_RESET}")


# --- Main Execution Logic ---

def main():
    """Main function to orchestrate the scan using imported modules."""

    # --- Argument Parsing for Logging and other controls ---
    # This parser will handle command-line arguments, starting with logging controls.
    parser = argparse.ArgumentParser(
        description="Guardian: Network Security Scanner.", # Updated Description
        formatter_class=argparse.RawTextHelpFormatter # Allows for better help text formatting
    )
    parser.add_argument(
        "--log-level",
        default="INFO", # Default logging level if not specified
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level for operational messages.\n"
             "DEBUG: Detailed information, typically of interest only when diagnosing problems.\n"
             "INFO: Confirmation that things are working as expected.\n"
             "WARNING: An indication that something unexpected happened, or indicative of some problem in the near future (e.g. 'disk space low'). The software is still working as expected.\n"
             "ERROR: Due to a more serious problem, the software has not been able to perform some function.\n"
             "CRITICAL: A serious error, indicating that the program itself may be unable to continue running."
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None, # By default, logs are not written to a file, only to the console.
        help="Path to a file where operational logs should be saved (e.g., guardian_run.log).\n"
             "If not specified, logs will only be output to the console."
    )
    parser.add_argument("--target-host", type=str, help="Target host (IP or hostname) for traceroute functionality.")
    # Add other future arguments here, for example:
    # parser.add_argument("--config", type=str, help="Path to a custom configuration file.")
    
    args = parser.parse_args()

    # --- Setup Logging ---
    # This MUST be one of the first actions to ensure logging is available globally.
    # It configures the root logger based on command-line arguments.
    try:
        setup_logging(log_level_str=args.log_level, log_file=args.log_file)
    except Exception as e:
        # This print is a last resort if logging setup itself fails.
        print(f"{COLOR_RED}Critical error during logging setup: {e}. Exiting.{COLOR_RESET}")
        return # Exit if logging cannot be initialized

    # Obtain the main logger for the guardian script's primary operations.
    # Child loggers (e.g., "guardian.module_wrapper") will inherit settings from the root logger.
    logger = logging.getLogger("guardian.main")

    start_time = time.time()
    print_banner() # Keep banner as print for its specific formatting and prominence.

    logger.info("Guardian scan initiated. Log level: %s.", args.log_level.upper())

    if os.geteuid() != 0:
         # Log a warning if not running as root, as it impacts script capabilities.
         logger.warning("Script not running as root. Some checks require root privileges for complete information (e.g., shadow file, sudoers, process details, some sysctl). Results may be limited.")
         # The original script had a "\\n" here, but loggers handle newlines automatically.

    # Use a Manager for shared state between processes
    with multiprocessing.Manager() as manager:
        # Create managed dictionaries for findings and statistics
        # Findings use lists within the dict, as they are appended to.
        managed_findings = manager.dict({
            SEVERITY_CRITICAL: manager.list(),
            SEVERITY_HIGH: manager.list(),
            SEVERITY_MEDIUM: manager.list(),
            SEVERITY_LOW: manager.list(),
            SEVERITY_INFO: manager.list(),
        })
        # Statistics use a standard dict, where modules populate their own top-level key.
        # Modules should strive to use nested dictionaries or simple types for stats.
        managed_stats = manager.dict()

        # --- Define Processes for Modules --- #
        # List the WRAPPER functions to run
        modules_to_run = [
            run_network_scan_wrapper,
            run_ssh_analysis_wrapper,
            run_log_analysis_wrapper,
            run_services_timers_wrapper,
            run_environment_detection_wrapper,
            run_traceroute_analysis_wrapper, # Added traceroute wrapper
            # Add future module wrappers here
            run_local_traffic_analysis_wrapper,
            run_local_mitm_detection_wrapper, # Renamed from run_arp_detection_wrapper
            run_dns_spoofing_detection_wrapper,
            # Non-network modules and their wrappers are removed
        ]

        # Simpler approach for starting processes:
        # Create standard module processes
        standard_processes = []
        
        # Initialize managed_stats sub-dictionaries for modules that require it
        managed_stats['mitm_detection'] = manager.dict() # For ARP detection module
        
        for module_wrapper_func in modules_to_run:
            p = multiprocessing.Process(target=module_wrapper_func, args=(managed_stats, managed_findings))
            standard_processes.append(p)
        
        # Add conditional processes like traceroute and target profiler
        if args.target_host:
            if 'network' not in managed_stats: # Should already exist if network_scan runs, but good check
                managed_stats['network'] = manager.dict()
            managed_stats['network']['traceroute_results'] = manager.dict() # For traceroute
            
            if 'target_profiles' not in managed_stats:
                managed_stats['target_profiles'] = manager.dict() # For target profiler

            p_trace = multiprocessing.Process(target=run_traceroute_wrapper, args=(managed_stats, managed_findings, args.target_host))
            standard_processes.append(p_trace)
            
            p_profile = multiprocessing.Process(target=run_target_profiling_wrapper, args=(managed_stats, managed_findings, args.target_host))
            standard_processes.append(p_profile)

        # Start all processes
        logger.info("--- Launching All Modules Concurrently ---")
        for p in standard_processes:
            p.start()
        
        processes = standard_processes # Update main processes list

        # --- Wait for Processes to Complete --- #
        # Log that the script is now waiting for module completion.
        logger.info("--- Waiting for modules to complete ---")
        for p in processes:
            p.join() # Wait for each process to finish

        # Log the completion of all modules.
        logger.info("--- All modules finished ---")

        # --- Reporting --- #
        # Pass the managed dictionaries (which now contain results) to the summary function
        # Convert back to regular dict/list for easier processing in display_summary
        # and JSON serialization
        final_findings = {k: list(v) for k, v in managed_findings.items()}
        final_stats = dict(managed_stats) # Convert the top-level managed dict

        display_summary(final_findings, final_stats)

        # Optional: Save full report
        try: # Added try block here
            report_file = f"guardian_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            # Data is already converted above
            report_data = {
                "statistics": final_stats,
                "findings": final_findings
            }
            with open(report_file, "w") as f:
                json.dump(report_data, f, indent=4)
            # Log the successful saving of the report.
            logger.info(f"Full report saved to {report_file}")
        except Exception as e: # Added except block
            # Log an error if saving the report fails.
            logger.error(f"Error saving report to {report_file}: {e}")

    end_time = time.time()
    # Log the total scan completion time.
    logger.info(f"Scan completed in {end_time - start_time:.2f} seconds.")

# --- The multiprocessing main execution block ---
if __name__ == "__main__":
    # Necessary for multiprocessing on some platforms (Windows, macOS with 'spawn' start method)
    multiprocessing.freeze_support()
    # start_time = time.time() # Start time is now handled within main()
    main()
