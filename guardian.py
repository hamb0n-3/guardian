#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Author: hamb0n-3

"""
Guardian: Advanced Host and Network Defense Scanner (Multiprocess Enabled)

This script orchestrates various modules to gather system and network
information, analyze it for potential security vulnerabilities and
misconfigurations, and provide actionable findings with a focus on
operational security heuristics.
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
from modules import system_info
from modules import network_scan
from modules import process_analysis
from modules import ssh_analysis
from modules import user_analysis
from modules import file_system
from modules import kernel_params
# Import newly added modules
from modules import log_analysis
from modules import services_timers
from modules import environment_detection

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

def run_system_info_wrapper(managed_stats, managed_findings):
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_system_info_wrapper.__name__}")
    module_name = system_info.get_system_info.__name__
    try:
        logger.info(f"Starting module: {module_name}")
        system_info.get_system_info(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

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

def run_process_analysis_wrapper(managed_stats, managed_findings):
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_process_analysis_wrapper.__name__}")
    module_name = process_analysis.get_running_processes.__name__
    try:
        logger.info(f"Starting module: {module_name}")
        process_analysis.get_running_processes(managed_stats, managed_findings, add_finding_mp)
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

def run_user_analysis_wrapper(managed_stats, managed_findings):
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_user_analysis_wrapper.__name__}")
    module_name = user_analysis.check_user_accounts.__name__
    try:
        logger.info(f"Starting module: {module_name}")
        user_analysis.check_user_accounts(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_file_system_scan_wrapper(managed_stats, managed_findings):
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_file_system_scan_wrapper.__name__}")
    module_name = file_system.find_sensitive_files_and_permissions.__name__
    try:
        logger.info(f"Starting module: {module_name}")
        # Can pass specific args here if needed, e.g., search_paths, max_depth
        file_system.find_sensitive_files_and_permissions(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_kernel_params_wrapper(managed_stats, managed_findings):
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_kernel_params_wrapper.__name__}")
    module_name = kernel_params.check_kernel_parameters.__name__
    try:
        logger.info(f"Starting module: {module_name}")
        kernel_params.check_kernel_parameters(managed_stats, managed_findings, add_finding_mp)
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

def run_services_timers_wrapper(managed_stats, managed_findings):
    """Wrapper to run the services and timers check module in a separate process."""
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_services_timers_wrapper.__name__}")
    module_name = "services_timers (systemd)"
    try:
        logger.info(f"Starting module: {module_name}")
        # Call the primary function from the services_timers module
        services_timers.check_systemd_units(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

def run_environment_detection_wrapper(managed_stats, managed_findings):
    """Wrapper to run the environment detection module in a separate process."""
    # Obtain a logger specific to this wrapper function
    logger = logging.getLogger(f"guardian.{run_environment_detection_wrapper.__name__}")
    module_name = "environment_detection (VM/Container)"
    try:
        logger.info(f"Starting module: {module_name}")
        # Call the primary function from the environment_detection module
        environment_detection.detect_environment(managed_stats, managed_findings, add_finding_mp)
        logger.info(f"Finished module: {module_name}")
    except Exception as e:
        logger.error(f"Process Error in {module_name}: {e}")
        add_finding_mp(managed_findings, SEVERITY_HIGH, f"Module Error: {module_name}", f"Failed to run: {e}")

# --- Helper Functions (Output Formatting) ---

def print_banner():
    """Prints a cool banner for the script."""
    print(f"{COLOR_CYAN}{COLOR_BOLD}")
    print("#############################################")
    print("#            Guardian Scanner             #")
    print("#        Advanced Defense & OPSEC         #")
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
    """Displays a summary of findings and statistics from managed dicts."""
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}--- Scan Summary ---{COLOR_RESET}")

    # Findings Summary
    print(f"{COLOR_YELLOW}{COLOR_BOLD}Findings by Severity:{COLOR_RESET}")
    # Convert managed list proxy to list for reliable length check and iteration
    total_findings = sum(len(list(v)) for v in final_findings.values())
    if total_findings == 0:
        print(f"  {COLOR_GREEN}No significant security findings reported.{COLOR_RESET}")
    else:
        severity_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
        for severity in severity_order:
            # Convert managed list proxy to list for len()
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

    if 'system' in stats_copy:
        sys_stats = stats_copy['system'] # Already a dict if populated correctly
        print(f"  System: {sys_stats.get('os_name', 'N/A')} {sys_stats.get('os_version', 'N/A')} ({sys_stats.get('hostname', 'N/A')})")
        print(f"  CPU/Mem Usage: {sys_stats.get('cpu_percent', 'N/A')}% / {sys_stats.get('memory_used_percent', 'N/A')}%")
        stats_printed = True
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
        if 'count' in proc_stats:
            print(f"  Running Processes: {proc_stats.get('count', 0)} found")
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
    if 'files' in stats_copy:
        file_stats = stats_copy['files']
        counts = {
            'Sensitive Files': len(list(file_stats.get('sensitive_files_found', []))),
            'World-Writable Files': len(list(file_stats.get('world_writable_files', []))),
            'World-Writable Dirs (No Sticky)': len(list(file_stats.get('world_writable_dirs_no_sticky', []))),
            'Non-Standard SUID/SGID': len(list(file_stats.get('suid_sgid_files', []))),
            'Dangling Ownership': len(list(file_stats.get('dangling_files', [])))
        }
        for name, count in counts.items():
            if count > 0:
                print(f"  File System: {name}: {count} found")
                stats_printed = True
    if 'kernel_params' in stats_copy:
        kp_stats = stats_copy['kernel_params']
        checked = kp_stats.get('checked_count', 0)
        errors = len(list(kp_stats.get('errors', [])))
        print(f"  Kernel Params (sysctl): {checked} checked", end='')
        if errors > 0:
            print(f" ({errors} errors/warnings)")
        else:
            print()
        stats_printed = True

    # --- NEW Module Statistics ---
    if 'environment' in stats_copy:
        env_stats = stats_copy['environment']
        detection_method = env_stats.get('detection_method', 'N/A')
        env_type = env_stats.get('type', 'Bare Metal / Unknown')
        print(f"  Environment: {env_type} (Detected via: {detection_method})")
        stats_printed = True

    if 'logs' in stats_copy:
        log_stats = stats_copy['logs']
        auth_stats = log_stats.get('auth_log', {}) # Safely get sub-dict
        if auth_stats: # Check if auth_log stats exist
             analyzed_path = auth_stats.get('analyzed_path', '/var/log/auth.log')
             lines = auth_stats.get('lines_processed', 0)
             failed_logins = len(list(auth_stats.get('failed_logins', [])))
             sudo_events = len(list(auth_stats.get('sudo_events', [])))
             ssh_logins = len(list(auth_stats.get('ssh_logins', [])))
             print(f"  Log Analysis ({os.path.basename(analyzed_path)}): {lines} lines processed")
             if failed_logins > 0: print(f"    Failed Logins Found: {failed_logins}")
             if sudo_events > 0: print(f"    Sudo Events Found: {sudo_events}")
             if ssh_logins > 0: print(f"    SSH Logins Found: {ssh_logins}")
             stats_printed = True

    if 'services' in stats_copy:
        svc_stats = stats_copy['services']
        units_checked = svc_stats.get('units_checked_count', 0)
        timers_checked = svc_stats.get('timers_checked_count', 0)
        risky_services = len(list(svc_stats.get('risky_services_found', [])))
        frequent_timers = len(list(svc_stats.get('frequent_timers_found', [])))
        print(f"  Systemd Units: {units_checked} services checked, {timers_checked} timers checked")
        if risky_services > 0: print(f"    Potentially Risky Services: {risky_services}")
        if frequent_timers > 0: print(f"    Frequent Timers Flagged: {frequent_timers}")
        stats_printed = True
    # --- End NEW Module Statistics ---

    if not stats_printed:
        print(f"  {COLOR_YELLOW}No statistics gathered or modules run.{COLOR_RESET}")

    # Detailed Findings
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}--- Detailed Findings ---{COLOR_RESET}")
    if total_findings > 0:
         severity_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
         for severity in severity_order:
             if final_findings[severity]:
                 for finding in final_findings[severity]:
                     print_finding(severity, finding['title'], finding['description'], finding.get('recommendation', 'N/A'))
    else:
        print(f"  {COLOR_GREEN}No detailed findings to display.{COLOR_RESET}")


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
        description="Guardian: Advanced Host and Network Defense Scanner.",
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
            run_system_info_wrapper,
            run_network_scan_wrapper,
            run_process_analysis_wrapper,
            run_ssh_analysis_wrapper,
            run_user_analysis_wrapper,
            run_file_system_scan_wrapper,
            run_kernel_params_wrapper,
            # --- Add NEW module wrappers ---
            run_log_analysis_wrapper,
            run_services_timers_wrapper,
            run_environment_detection_wrapper,
            # Add future module wrappers here
        ]

        processes = []
        # Log the start of module launching phase.
        logger.info("--- Launching Modules Concurrently ---")
        for module_wrapper_func in modules_to_run:
            # Pass the managed dicts to each process target function
            p = multiprocessing.Process(target=module_wrapper_func, args=(managed_stats, managed_findings))
            processes.append(p)
            p.start()
            # Print statement moved to inside the wrapper for better timing (now logger call inside wrapper)

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
