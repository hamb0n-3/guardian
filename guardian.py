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
    # Removed 'services' and 'environment' sections from summary as per refactoring goal

    if not stats_printed:
        print(f"  {COLOR_YELLOW}No network-related statistics gathered or modules run.{COLOR_RESET}")

    # --- Interactive Detailed Findings ---
    if total_findings > 0:
        print(f"\n{COLOR_CYAN}{COLOR_BOLD}--- Detailed Findings ---{COLOR_RESET}")
        
        severity_map = {
            'C': SEVERITY_CRITICAL,
            'H': SEVERITY_HIGH,
            'M': SEVERITY_MEDIUM,
            'L': SEVERITY_LOW,
            'I': SEVERITY_INFO
        }
        # Order for displaying if 'All' is chosen
        severity_display_order_all = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]

        while True: # Loop for iterative selection
            prompt_message = (
                f"\nSelect severities to view (e.g., C,H or M), or:\n"
                f"  (C)ritical, (H)igh, (M)edium, (L)ow, (I)nfo\n"
                f"  (A)ll findings, (Q)uit detailed view: "
            )
            
            user_input_raw = ""
            try:
                user_input_raw = input(f"{COLOR_YELLOW}{prompt_message}{COLOR_RESET}").strip().upper()
            except EOFError: # Non-interactive environment
                print(f"  {COLOR_YELLOW}No input received (non-interactive environment?). Skipping interactive drill-down.{COLOR_RESET}")
                print(f"  {COLOR_YELLOW}All findings are available in the JSON report.{COLOR_RESET}")
                break # Exit the while loop
            except Exception as e: # Catch other potential input errors
                print(f"  {COLOR_RED}An error occurred during input: {e}. Skipping detailed findings.{COLOR_RESET}")
                break # Exit the while loop

            if not user_input_raw: # User pressed Enter without input
                print(f"  {COLOR_YELLOW}No selection made. Please enter a valid option.{COLOR_RESET}")
                continue # Continue to next iteration of the while loop

            # Handle single char 'Q' or 'N' for quit, or 'A' for all, before splitting by comma
            if user_input_raw == 'Q' or user_input_raw == 'N':
                print(f"  {COLOR_GREEN}Exiting detailed findings view.{COLOR_RESET}")
                break # Exit the while loop
            
            if user_input_raw == 'A':
                print(f"  {COLOR_GREEN}Displaying all findings:{COLOR_RESET}")
                any_displayed_for_all = False
                for severity_level in severity_display_order_all:
                    findings_for_level = final_findings.get(severity_level, [])
                    if findings_for_level:
                        print(f"  {COLOR_CYAN}--- Findings for {severity_level} ---{COLOR_RESET}")
                        for finding in findings_for_level:
                            print_finding(severity_level, finding['title'], finding['description'], finding.get('recommendation', 'N/A'))
                            any_displayed_for_all = True
                if not any_displayed_for_all:
                    print(f"  {COLOR_GREEN}No findings were reported across all severities.{COLOR_RESET}")
                break # Exit the while loop after 'A' (as 'All' is a terminal action for the loop)

            # Process comma-separated inputs
            choices = [choice.strip() for choice in user_input_raw.split(',')]
            processed_any_valid_choice_this_iteration = False

            for selected_severity_code in choices:
                if not selected_severity_code: # Skip empty strings if input was e.g. "C,,"
                    continue

                # Check again for Q/N/A within comma-separated values, though less conventional.
                # Primary handling for these is as standalone inputs.
                if selected_severity_code == 'Q' or selected_severity_code == 'N':
                    print(f"  {COLOR_GREEN}Exiting detailed findings view (Quit signal found in list).{COLOR_RESET}")
                    return # Exit display_summary function entirely if Q/N found within list
                
                if selected_severity_code == 'A':
                    print(f"  {COLOR_GREEN}Displaying all findings (All signal found in list):{COLOR_RESET}")
                    # This inner 'A' will also display all and then we should break the outer loop.
                    # To avoid deep breaks, just call the 'A' logic and then return from display_summary.
                    # This means an 'A' within a list like "C,A,H" will show C, then all, then stop.
                    all_displayed = False
                    for sev_level in severity_display_order_all:
                        f_for_level = final_findings.get(sev_level, [])
                        if f_for_level:
                            print(f"  {COLOR_CYAN}--- Findings for {sev_level} ---{COLOR_RESET}")
                            for f_item in f_for_level:
                                print_finding(sev_level, f_item['title'], f_item['description'], f_item.get('recommendation', 'N/A'))
                                all_displayed = True
                    if not all_displayed:
                        print(f"  {COLOR_GREEN}No findings were reported across all severities.{COLOR_RESET}")
                    return # Exit display_summary function

                mapped_severity = severity_map.get(selected_severity_code)

                if mapped_severity:
                    findings_for_level = final_findings.get(mapped_severity, [])
                    if findings_for_level:
                        print(f"  {COLOR_CYAN}--- Findings for {mapped_severity} ---{COLOR_RESET}")
                        for finding in findings_for_level:
                            print_finding(mapped_severity, finding['title'], finding['description'], finding.get('recommendation', 'N/A'))
                        processed_any_valid_choice_this_iteration = True
                    else:
                        print(f"  {COLOR_YELLOW}No findings reported for severity '{selected_severity_code}' ({mapped_severity}).{COLOR_RESET}")
                        processed_any_valid_choice_this_iteration = True # It was a valid code, just no findings
                else:
                    print(f"  {COLOR_RED}Warning: Unknown severity code '{selected_severity_code}'. It will be ignored.{COLOR_RESET}")
            
            if not processed_any_valid_choice_this_iteration and choices:
                 # This means user entered something, but none of it was a recognized severity code
                 # (or Q/A if we didn't handle them to break earlier)
                 # The individual warnings for unknown codes would have already printed.
                 # No additional general message needed here as specific errors are shown.
                 pass 
            # Loop continues for next prompt unless 'A' or 'Q'/"N" was processed to break/return.

    elif total_findings == 0:
        pass # Already handled by the initial check for total_findings
    else: # Should not be reached
        print(f"  {COLOR_GREEN}No findings reported by the scan.{COLOR_RESET}")


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
            # Non-network modules and their wrappers are removed
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
