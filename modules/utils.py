#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guardian Utilities: Helper functions and constants for the Guardian scanner.
"""

import subprocess
import os

# Define color codes for output formatting
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"

# Finding severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"


def run_command(command):
    """
    Executes a shell command safely and returns its output.
    Handles potential errors during execution.

    Args:
        command (list): The command and its arguments as a list.

    Returns:
        str: The standard output of the command, or None if an error occurs.
             Stderr is printed if an error occurs.
    """
    try:
        # Execute the command
        # We use check=True to raise CalledProcessError on non-zero exit codes
        # We capture stdout and stderr separately
        # text=True decodes output/error as text
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=15 # Add a timeout to prevent hanging
        )
        # Return the standard output, stripping trailing newline
        return result.stdout.strip()
    except FileNotFoundError:
        # Handle case where the command doesn't exist
        print(f"{COLOR_RED}Error: Command not found: {' '.join(command)}{COLOR_RESET}")
        return None
    except subprocess.CalledProcessError as e:
        # Handle errors during command execution (non-zero exit code)
        print(f"{COLOR_RED}Error executing command: {' '.join(command)}{COLOR_RESET}")
        print(f"  Exit Code: {e.returncode}")
        if e.stderr:
            print(f"  Stderr: {e.stderr.strip()}")
        return None
    except subprocess.TimeoutExpired:
        print(f"{COLOR_RED}Error: Command timed out: {' '.join(command)}{COLOR_RESET}")
        return None
    except Exception as e:
        # Catch any other unexpected exceptions
        print(f"{COLOR_RED}An unexpected error occurred while running command {' '.join(command)}: {e}{COLOR_RESET}")
        return None 