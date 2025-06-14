# workbench_cli/utils.py

import os
import json
import time
import logging
import argparse
import re
import requests
import typing 
import functools
from typing import Generator, Optional, Dict, Any, List, Union, Tuple, Callable

# Import Workbench class for type hinting and accessing constants/methods if needed
# Use relative import within the package
if typing.TYPE_CHECKING:
    from .api import Workbench

from .exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError,
    ProcessError,
    ProcessTimeoutError
)

# Assume logger is configured in main.py and get it
logger = logging.getLogger("workbench-cli")

# --- Error Handling Utilities ---
def _format_and_print_error(error: Exception, handler_name: str, params: argparse.Namespace):
    """
    Formats and prints a standardized error message for CLI users.
    
    This centralized function handles consistent error formatting across
    all handlers, eliminating duplicated error handling code.
    
    Args:
        error: The exception that occurred
        handler_name: Name of the handler where the error occurred
        params: Command line parameters
    """
    command = getattr(params, 'command', 'unknown')
    error_type = type(error).__name__
    
    # Get error details if available (for our custom errors)
    error_message = getattr(error, 'message', str(error))
    error_code = getattr(error, 'code', None)
    error_details = getattr(error, 'details', {})
    
    # Determine if this is a read-only operation
    read_only_commands = {'show-results', 'evaluate-gates', 'download-reports'}
    is_read_only = command in read_only_commands
    
    # Add context-specific help based on error type
    if isinstance(error, ProjectNotFoundError):
        if is_read_only:
            print(f"\n❌ Cannot continue: The requested project does not exist")
            print(f"   Project '{getattr(params, 'project_name', 'unknown')}' was not found in your Workbench instance.")
            print(f"\n💡 Please check:")
            print(f"   • The project name is spelled correctly")
            print(f"   • The project exists in your Workbench instance")
            print(f"   • You have access to the project")
        else:
            print(f"\n❌ Error executing '{command}' command: {error_message}")
            print(f"  → Project '{getattr(params, 'project_name', 'unknown')}' was not found")
            print(f"  → Check the project name or use --create-project to create it")
    
    elif isinstance(error, ScanNotFoundError):
        if is_read_only:
            print(f"\n❌ Cannot continue: The requested scan does not exist")
            scan_name = getattr(params, 'scan_name', 'unknown')
            project_name = getattr(params, 'project_name', None)
            
            if project_name:
                print(f"   Scan '{scan_name}' was not found in project '{project_name}'.")
            else:
                print(f"   Scan '{scan_name}' was not found in your Workbench instance.")
            
            print(f"\n💡 Please check:")
            print(f"   • The scan name is spelled correctly")
            if project_name:
                print(f"   • The scan exists in the '{project_name}' project")
            else:
                print(f"   • The scan exists in your Workbench instance")
                print(f"   • Consider specifying --project-name if the scan is in a specific project")
            print(f"   • You have access to the scan")
        else:
            print(f"\n❌ Error executing '{command}' command: {error_message}")
            print(f"  → Scan '{getattr(params, 'scan_name', 'unknown')}' was not found")
            if hasattr(params, 'project_name'):
                print(f"  → Check the scan name or verify it exists in project '{params.project_name}'")
            else:
                print(f"  → Check the scan name or specify --project-name if it exists in a specific project")
    
    elif isinstance(error, NetworkError):
        print(f"\n❌ Network connectivity issue")
        print(f"   {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • The Workbench server is accessible")
        print(f"   • The API URL is correct: {getattr(params, 'api_url', '<not specified>')}")
    
    elif isinstance(error, ApiError):
        print(f"\n❌ Workbench API error")
        print(f"   {error_message}")
        
        if error_code:
            print(f"   Error code: {error_code}")
            
            # Special handling for Git repository access errors
            if error_code == "git_repository_access_error":
                print(f"\n💡 Git repository access issue:")
                print(f"   • Check that the Git URL is correct and accessible from the Workbench server")
                print(f"   • Ensure any required authentication is properly configured")
            else:
                print(f"\n💡 The Workbench API reported an issue with your request")
    
    elif isinstance(error, ProcessTimeoutError):
        print(f"\n❌ Operation timed out")
        print(f"   {error_message}")
        print(f"\n💡 Consider increasing the timeout values:")
        print(f"   • --scan-number-of-tries (current: {getattr(params, 'scan_number_of_tries', 'default')})")
        print(f"   • --scan-wait-time (current: {getattr(params, 'scan_wait_time', 'default')})")
    
    elif isinstance(error, ProcessError):
        print(f"\n❌ Workbench process error")
        print(f"   {error_message}")
        print(f"\n💡 A Workbench process failed to complete successfully")
    
    elif isinstance(error, FileSystemError):
        print(f"\n❌ File system error")
        print(f"   {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • File permissions are correct")
        print(f"   • All specified paths exist")
        if hasattr(params, 'path'):
            print(f"   • Path specified: {params.path}")
    
    elif isinstance(error, ValidationError):
        print(f"\n❌ Invalid input or configuration")
        print(f"   {error_message}")
        print(f"\n💡 Please check your command-line arguments and input files")
    
    elif isinstance(error, ConfigurationError):
        print(f"\n❌ Configuration error")
        print(f"   {error_message}")
        print(f"\n💡 Please check your command-line arguments and configuration")
    
    elif isinstance(error, CompatibilityError):
        print(f"\n❌ Compatibility issue")
        print(f"   {error_message}")
        print(f"\n💡 The requested operation is not compatible with the scan's current state")
    
    elif isinstance(error, AuthenticationError):
        print(f"\n❌ Authentication failed")
        print(f"   {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • Your API credentials are correct")
        print(f"   • You have the necessary permissions")
    
    else:
        # Generic error formatting for unexpected errors
        print(f"\n❌ Error executing '{command}' command: {error_message}")
    
    # Show error code if available (and not already shown)
    if error_code and not isinstance(error, (ApiError, ProcessTimeoutError)):
        print(f"\nError code: {error_code}")
    
    # Show details in verbose mode
    if getattr(params, 'verbose', False) and error_details:
        print("\nDetailed error information:")
        for key, value in error_details.items():
            print(f"  • {key}: {value}")
    
    # Add help text only for non-read-only operations or when in verbose mode
    if not is_read_only or getattr(params, 'verbose', False):
        print(f"\nFor more details, run with --log DEBUG for verbose output")

def handler_error_wrapper(handler_func: Callable) -> Callable:
    """
    A decorator that wraps handler functions with standardized error handling.
    
    This wrapper ensures consistent error handling across all handlers, reducing
    code duplication and ensuring all exceptions are properly logged and handled.
    The wrapper catches exceptions, formats user-friendly error messages, and
    re-raises the exceptions for proper exit code handling in the main CLI.
    
    Args:
        handler_func: The handler function to wrap
        
    Returns:
        The wrapped handler function with error handling
    
    Example:
        @handler_error_wrapper
        def handle_scan(workbench, params):
            # Implementation without try/except blocks
            ...
    """
    @functools.wraps(handler_func)
    def wrapper(workbench, params):
        try:
            # Get the handler name for better error messages
            handler_name = handler_func.__name__
            command_name = params.command if hasattr(params, 'command') else 'unknown'
            logger.debug(f"Starting {handler_name} for command '{command_name}'")
            
            # Call the actual handler function
            return handler_func(workbench, params)
            
        except (ProjectNotFoundError, ScanNotFoundError, FileSystemError, 
                ApiError, NetworkError, ProcessError, ProcessTimeoutError, 
                ValidationError, CompatibilityError, ConfigurationError, 
                AuthenticationError) as e:
            # These exceptions are expected and properly formatted already
            # Format and display error message in standardized format
            logger.debug(f"Expected error in {handler_func.__name__}: {type(e).__name__}: {getattr(e, 'message', str(e))}")
            _format_and_print_error(e, handler_func.__name__, params)
            # Re-raise the exception for proper exit code handling
            raise
            
        except Exception as e:
            # Unexpected errors get wrapped in a WorkbenchCLIError
            logger.error(f"Unexpected error in {handler_func.__name__}: {e}", exc_info=True)
            
            # Create a WorkbenchCLIError with detailed info
            cli_error = WorkbenchCLIError(
                f"Failed to execute {params.command if hasattr(params, 'command') else 'command'}: {str(e)}",
                details={"error": str(e), "handler": handler_func.__name__}
            )
            
            # Format and display the error message
            _format_and_print_error(cli_error, handler_func.__name__, params)
            
            # Raise the wrapped error for proper exit code handling
            raise cli_error
            
    return wrapper

# --- Standard Scan Flow ---
def _assert_scan_is_idle(
    workbench: 'Workbench',
    scan_code: str,
    params: argparse.Namespace,
    process_types_to_check: List[str]
):
    """
    Checks if specified background processes for a scan are idle (not RUNNING or QUEUED).
    If a process is running/queued, waits for it to finish.

    Args:
        workbench: The Workbench API client instance.
        scan_code: The code of the scan to check.
        params: Command-line parameters (used for wait settings).
        process_types_to_check: List of process types (e.g., ["SCAN", "DEPENDENCY_ANALYSIS", "GIT_CLONE"]).

    Raises:
        ProcessError: If checking status fails or if waiting for a running process fails/times out.
        ApiError: If API calls fail unexpectedly.
        NetworkError: If network issues occur.
    """
    logger.debug(f"Asserting idle status for processes {process_types_to_check} on scan '{scan_code}'...")

    while True: # Loop until all processes are confirmed idle in one pass
        all_processes_idle_this_pass = True
        logger.debug("Starting a new pass to check idle status...")

        for process_type in process_types_to_check:
            process_type_upper = process_type.upper()
            logger.debug(f"Checking status for process type: {process_type_upper}")
            current_status = "UNKNOWN"
            status_data = None

            try:
                if process_type_upper == "GIT_CLONE":
                    # Use the specific check for Git clone status
                    status_data = workbench._send_request({
                        "group": "scans",
                        "action": "check_status_download_content_from_git",
                        "data": {"scan_code": scan_code}
                    })
                    # Git clone status is stored directly in 'data' field, not in a nested structure
                    if isinstance(status_data.get("data"), str):
                        current_status = status_data.get("data", "UNKNOWN").upper()
                    else:
                        # If it's not a string, pass the data object to the accessor
                        current_status = workbench._standard_scan_status_accessor(status_data.get("data", {}))
                elif process_type_upper in ["SCAN", "DEPENDENCY_ANALYSIS", "EXTRACT_ARCHIVES"]:
                    # Use the generic get_scan_status
                    status_data = workbench.get_scan_status(process_type_upper, scan_code)
                    # Use the standard accessor to get a normalized status
                    current_status = workbench._standard_scan_status_accessor(status_data)
                else:
                    logger.warning(f"Unknown process type '{process_type_upper}' requested for idle check. Skipping.")
                    continue # Skip unknown types in this pass

                logger.debug(f"Status check response for {process_type_upper}: {status_data}")
                logger.debug(f"Current status for {process_type_upper}: {current_status}")

            except ScanNotFoundError:
                # If the scan doesn't exist, it's implicitly idle for this process.
                logger.debug(f"Scan '{scan_code}' not found during idle check for {process_type_upper}. Assuming idle.")
                print(f"  - {process_type_upper}: Not found (considered idle).")
                continue # Move to the next process type in this pass
            except (ApiError, NetworkError) as e:
                logger.error(f"Failed to check status for {process_type_upper} on scan '{scan_code}': {e}", exc_info=True)
                raise ProcessError(f"Cannot proceed: Failed to check status for {process_type_upper} due to API/Network error: {e}") from e
            except Exception as e:
                logger.error(f"Unexpected error checking status for {process_type_upper} on scan '{scan_code}': {e}", exc_info=True)
                raise ProcessError(f"Cannot proceed: Unexpected error checking status for {process_type_upper}: {e}") from e

            # --- Wait if Running or Queued ---
            if current_status in ["RUNNING", "QUEUED", "NOT FINISHED"]:
                all_processes_idle_this_pass = False # Mark that we found a running process
                print(f"  - {process_type_upper}: Status is {current_status}. Waiting for completion...")
                logger.info(f"Existing {process_type_upper} for '{scan_code}' is {current_status}. Waiting...")
                try:
                    if process_type_upper == "GIT_CLONE":
                        workbench.wait_for_git_clone(scan_code, params.scan_number_of_tries, params.scan_wait_time)
                    else:
                        workbench.wait_for_scan_to_finish(process_type_upper, scan_code, params.scan_number_of_tries, params.scan_wait_time)
                    print(f"  - {process_type_upper}: Previous run finished.")
                    logger.info(f"Previous {process_type_upper} for '{scan_code}' finished.")
                    # --- CRITICAL: Break inner loop to restart checks from the beginning ---
                    logger.debug(f"Breaking inner loop after waiting for {process_type_upper} to re-check all statuses.")
                    break # Exit the 'for' loop and restart the 'while' loop
                except (ProcessTimeoutError, ProcessError) as wait_err:
                    logger.error(f"Waiting for existing {process_type_upper} on scan '{scan_code}' failed: {wait_err}", exc_info=True)
                    raise ProcessError(f"Cannot proceed: Waiting for existing {process_type_upper} failed: {wait_err}") from wait_err
                except Exception as wait_exc:
                        logger.error(f"Unexpected error waiting for {process_type_upper} on scan '{scan_code}': {wait_exc}", exc_info=True)
                        raise ProcessError(f"Cannot proceed: Unexpected error waiting for {process_type_upper}: {wait_exc}") from wait_exc
            else:
                # Status is idle for this process type in this pass
                print(f"  - {process_type_upper}: Status is {current_status} (considered idle).")
                logger.debug(f"{process_type_upper} on scan '{scan_code}' is idle (Status: {current_status}).")

        # --- Check if the inner loop completed without breaking ---
        if all_processes_idle_this_pass:
            logger.debug("All processes confirmed idle in this pass. Exiting check loop.")
            break # Exit the 'while True' loop

    # If all checks passed
    print("All Scan status checks passed! Proceeding...")
    logger.debug(f"All required processes {process_types_to_check} for scan '{scan_code}' are idle.")

def _wait_for_scan_completion(workbench: 'Workbench', params: argparse.Namespace, scan_code: str) -> Tuple[bool, bool, Dict[str, float]]:
    """
    Wait for KB Scan and optionally Dependency Analysis to complete.
    This is a generalized version of the waiting pattern used in several handlers.
    
    Args:
        workbench: The Workbench API client instance
        params: Command-line parameters with scan_number_of_tries and scan_wait_time
        scan_code: The scan code to check status for
        
    Returns:
        Tuple[bool, bool, Dict[str, float]]: A tuple of (scan_completed, da_completed, durations)
    """
    scan_completed = False
    da_completed = False
    
    # Initialize timing dictionary
    durations = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0
    }
    
    # --- Check KB Scan Status and Wait if Needed ---
    print("\nEnsuring the Scan finished...")
    try:
        kb_status_data = workbench.get_scan_status("SCAN", scan_code)
        kb_status = kb_status_data.get("status", "UNKNOWN").upper()
        logger.debug(f"Current Scan status: {kb_status}")
        
        # Only proceed if scan is in a final state (FINISHED, FAILED, CANCELLED)
        # Otherwise wait for it to complete
        if kb_status not in {"FINISHED", "FAILED", "CANCELLED"}:
            print("KB Scan is in progress. Waiting for completion...")
            kb_scan_start_time = time.time()
            
            workbench.wait_for_scan_to_finish(
                "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
            )
            
            # Record KB scan duration from waiting
            durations["kb_scan"] = time.time() - kb_scan_start_time
            
            # Re-check status after waiting
            kb_status_data = workbench.get_scan_status("SCAN", scan_code)
            kb_status = kb_status_data.get("status", "UNKNOWN").upper()
        
        # Check final status
        scan_completed = kb_status == "FINISHED"
        if scan_completed:
            print("KB Scan has completed successfully.")
        else:
            print(f"KB Scan status is {kb_status}, not FINISHED.")
            return scan_completed, da_completed, durations

    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        print(f"\nError checking/waiting for KB Scan completion: {e}")
        logger.error(f"Error checking/waiting for KB scan '{scan_code}': {e}", exc_info=True)
        return False, False, durations
    except Exception as e:
        print(f"\nUnexpected error checking KB Scan status: {e}")
        logger.error(f"Unexpected error checking KB scan '{scan_code}' status: {e}", exc_info=True)
        return False, False, durations
    
    # --- Check Dependency Analysis Status and Wait if Needed ---
    # Only proceed to dependency analysis if KB scan completed successfully
    print("\nEnsuring Dependency Analysis finished...")
    try:
        da_status_data = workbench.get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
        da_status = da_status_data.get("status", "UNKNOWN").upper()
        logger.debug(f"Current Dependency Analysis status: {da_status}")
        
        # Wait for dependency analysis if it's in progress
        # "NEW" means it hasn't been started, which is acceptable
        if da_status not in {"FINISHED", "FAILED", "CANCELLED", "NEW"}:
            print("Dependency Analysis is in progress. Waiting for completion...")
            da_start_time = time.time()
            
            workbench.wait_for_scan_to_finish(
                "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time
            )
            
            # Record DA duration from waiting
            durations["dependency_analysis"] = time.time() - da_start_time
            
            # Re-check status after waiting
            da_status_data = workbench.get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
            da_status = da_status_data.get("status", "UNKNOWN").upper()
        
        # Check final status - consider both FINISHED and NEW (not run) as valid for our purposes
        da_completed = da_status == "FINISHED"
        if da_status == "NEW":
            print("Dependency Analysis has not been run for this scan.")
        elif da_completed:
            print("Dependency Analysis has completed successfully.")
        else:
            print(f"Dependency Analysis status is {da_status}, not FINISHED.")

    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        print(f"\nError checking/waiting for Dependency Analysis completion: {e}")
        logger.warning(f"Error checking/waiting for Dependency Analysis for scan '{scan_code}': {e}", exc_info=True)
        # We continue anyway if DA fails but KB scan succeeded
    except Exception as e:
        print(f"\nUnexpected error checking Dependency Analysis status: {e}")
        logger.warning(f"Unexpected error checking Dependency Analysis status for scan '{scan_code}': {e}", exc_info=True)
        # Continue even if there was an error checking DA status
    
    return scan_completed, da_completed, durations

# --- Scan Flow and Result Processing ---
def format_duration(duration_seconds: Optional[Union[int, float]]) -> str:
    """Formats a duration in seconds into a 'X minutes, Y seconds' string."""
    if duration_seconds is None:
        return "N/A"
    try:
        duration_seconds = round(float(duration_seconds)) # Ensure float then round
    except (ValueError, TypeError):
        return "Invalid Duration" # Handle non-numeric input

    minutes = int(duration_seconds // 60)
    seconds = int(duration_seconds % 60)

    if minutes > 0 and seconds > 0:
        return f"{minutes} minutes, {seconds} seconds"
    elif minutes > 0:
        return f"{minutes} minutes"
    elif seconds == 1:
         return f"{seconds} second" # Singular second
    else:
        return f"{seconds} seconds" # Plural seconds or zero

def _print_operation_summary(params: argparse.Namespace, da_completed: bool, project_code: str, scan_code: str, durations: Dict[str, float] = None):
    """
    Prints a standardized summary of the scan operations performed and settings used.
    
    Args:
        params: Command line parameters
        da_completed: Whether dependency analysis completed successfully
        project_code: Project code associated with the scan
        scan_code: Scan code of the operation
        durations: Dictionary containing operation durations in seconds
    """
    durations = durations or {}  # Initialize to empty dict if None
    
    print(f"\n--- Operation Summary ---")

    print("Workbench CLI Operation Details:")
    if params.command == 'scan':
        print(f"  - Method: Code Upload (using --path)")
        print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
        print(f"  - Recursive Archive Extraction: {getattr(params, 'recursively_extract_archives', 'N/A')}")
        print(f"  - JAR File Extraction: {getattr(params, 'jar_file_extraction', 'N/A')}")
    elif params.command == 'scan-git':
        print(f"  - Method: Git Scan")
        print(f"  - Git Repository URL: {getattr(params, 'git_url', 'N/A')}")
        if getattr(params, 'git_tag', None):
            print(f"  - Git Tag: {params.git_tag}")
        elif getattr(params, 'git_branch', None):
            print(f"  - Git Branch: {params.git_branch}")
        elif getattr(params, 'git_commit', None):
            print(f"  - Git Commit: {params.git_commit}")
        else:
             print(f"  - Git Branch/Tag/Commit: Not Specified")
        if getattr(params, 'git_depth', None) is not None:
             print(f"  - Git Clone Depth: {params.git_depth}")
    elif params.command == 'import-da':
        print(f"  - Method: Dependency Analysis Import")
        print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
    else:
        print(f"  - Method: Unknown ({params.command})")

    if params.command in ['scan', 'scan-git']:
        print("\nScan Parameters:")
        print(f"  - Auto-ID File Licenses: {'Yes' if getattr(params, 'autoid_file_licenses', False) else 'No'}")
        print(f"  - Auto-ID File Copyrights: {'Yes' if getattr(params, 'autoid_file_copyrights', False) else 'No'}")
        print(f"  - Auto-ID Pending IDs: {'Yes' if getattr(params, 'autoid_pending_ids', False) else 'No'}")
        print(f"  - Delta Scan: {'Yes' if getattr(params, 'delta_scan', False) else 'No'}")
        print(f"  - Identification Reuse: {'Yes' if getattr(params, 'id_reuse', False) else 'No'}")
        if getattr(params, 'id_reuse', False):
            print(f"    - Reuse Type: {getattr(params, 'id_reuse_type', 'N/A')}")
            if getattr(params, 'id_reuse_type', '') in {"project", "scan"}:
                 print(f"    - Reuse Source Name: {getattr(params, 'id_reuse_source', 'N/A')}")

    print("\nAnalysis Performed:")
    kb_scan_performed = params.command in ['scan', 'scan-git'] and not getattr(params, 'dependency_analysis_only', False)
    
    # Add durations to output only for KB scan and Dependency Analysis
    if kb_scan_performed:
        kb_duration_str = format_duration(durations.get("kb_scan", 0)) if durations.get("kb_scan") else "N/A"
        print(f"  - Signature Scan: Yes (Duration: {kb_duration_str})")
    else:
        print(f"  - Signature Scan: No")
    
    if da_completed:
        da_duration_str = format_duration(durations.get("dependency_analysis", 0)) if durations.get("dependency_analysis") else "N/A"
        print(f"  - Dependency Analysis: Yes (Duration: {da_duration_str})")
    elif params.command == 'import-da':
        print(f"  - Dependency Analysis: Imported")
    else:
        print(f"  - Dependency Analysis: No")
    
    print("------------------------------------")

def determine_scans_to_run(params: argparse.Namespace) -> Dict[str, bool]:
    """
    Determines which scan processes to run based on the provided parameters.
    Handles the logic for scan modes (KB only, DA only, KB+DA) and checks for
    mutually exclusive parameters.
    
    Args:
        params: Command line parameters with scan options
        
    Returns:
        Dict[str, bool]: Dictionary with flags indicating which processes to run:
            - run_kb_scan: Whether to run KB scan
            - run_dependency_analysis: Whether to run dependency analysis
            
    Raises:
        ValidationError: If mutually exclusive parameters are provided in an invalid way
    """
    # Get relevant parameter values (with defaults if not present)
    run_dependency_analysis = getattr(params, 'run_dependency_analysis', False)
    dependency_analysis_only = getattr(params, 'dependency_analysis_only', False)
    
    # Default: Run KB scan only
    scan_operations = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Check for mutually exclusive parameters
    if run_dependency_analysis and dependency_analysis_only:
        # If both are specified, warn and use dependency_analysis_only mode
        logger.warning("Both --dependency-analysis-only and --run-dependency-analysis were specified.")
        logger.warning("Using --dependency-analysis-only mode (skipping KB scan).")
        print("\nWARNING: Both --dependency-analysis-only and --run-dependency-analysis were specified.")
        print("Using --dependency-analysis-only mode (skipping KB scan).")
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    # Handle dependency analysis only mode
    elif dependency_analysis_only:
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    # Handle KB scan + dependency analysis mode
    elif run_dependency_analysis:
        scan_operations["run_kb_scan"] = True
        scan_operations["run_dependency_analysis"] = True
    # Default is already set (KB scan only)
    
    logger.debug(f"Determined scan operations: {scan_operations}")
    return scan_operations

# --- Fetching, Displaying, and Saving Results ---
def _fetch_results(workbench: 'Workbench', params: argparse.Namespace, scan_code: str) -> Dict[str, Any]:
    """
    Fetches requested scan results based on --show-* flags.
    
    Args:
        workbench: The Workbench API client instance
        params: Command-line parameters
        scan_code: Scan code to fetch results for
        
    Returns:
        Dict[str, Any]: Dictionary containing all collected results
    """
    # Get flags from parameters
    should_fetch_licenses = getattr(params, 'show_licenses', False)
    should_fetch_components = getattr(params, 'show_components', False)
    should_fetch_dependencies = getattr(params, 'show_dependencies', False)
    should_fetch_metrics = getattr(params, 'show_scan_metrics', False)
    should_fetch_policy = getattr(params, 'show_policy_warnings', False)
    should_fetch_vulnerabilities = getattr(params, 'show_vulnerabilities', False)
    
    # Check if anything should be fetched
    if not (should_fetch_licenses or should_fetch_components or should_fetch_dependencies or 
            should_fetch_metrics or should_fetch_policy or should_fetch_vulnerabilities):
        print("\n=== No Results Requested ===")
        print("No results were requested, so nothing to show.")
        print("Add (--show-licenses, --show-components, --show-dependencies, --show-scan-metrics, --show-policy-warnings, --show-vulnerabilities) to see results.")
        return {}

    logger.debug("\n=== Fetching Requested Results ===")
    collected_results = {}
    
    # --- Fetch DA Results ---
    if should_fetch_licenses or should_fetch_dependencies:
        try:
            logger.debug(f"\nFetching Dependency Analysis results for '{scan_code}'...")
            da_results_data = workbench.get_dependency_analysis_results(scan_code)
            if da_results_data:
                logger.debug(f"Successfully fetched {len(da_results_data)} DA entries.")
                collected_results['dependency_analysis'] = da_results_data
            else:
                # API method handles "not run" or empty cases
                logger.debug("No Dependency Analysis data found or returned.")
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch Dependency Analysis results: {e}")
            logger.warning(f"Failed to fetch DA results for {scan_code}", exc_info=False)
        except Exception as e:  # Catch unexpected errors
            print(f"Warning: Unexpected error fetching Dependency Analysis results: {e}")
            logger.warning(f"Unexpected error fetching DA results for {scan_code}", exc_info=True)

    # --- Fetch Identified Licenses ---
    if should_fetch_licenses:
        try:
            logger.debug(f"\nLicenses for Identified Components in '{scan_code}'...")
            kb_licenses_raw = workbench.get_scan_identified_licenses(scan_code)
            kb_licenses_data = sorted(kb_licenses_raw, key=lambda x: x.get('identifier', '').lower())
            if kb_licenses_data:
                logger.debug(f"Successfully fetched {len(kb_licenses_data)} unique KB licenses.")
                collected_results['kb_licenses'] = kb_licenses_data
            else:
                logger.debug("No Licenses in Identified Components were returned.")
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch KB Identified Licenses: {e}")
            logger.warning(f"Failed to fetch KB licenses for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching KB Identified Licenses: {e}")
            logger.warning(f"Unexpected error fetching KB licenses for {scan_code}", exc_info=True)

    # --- Fetch Identified Components ---
    if should_fetch_components:
        try:
            logger.debug(f"\nFetching Identified Components for '{scan_code}'...")
            kb_components_raw = workbench.get_scan_identified_components(scan_code)
            kb_components_data = sorted(kb_components_raw, key=lambda x: (x.get('name', '').lower(), x.get('version', '')))
            if kb_components_data:
                logger.debug(f"Successfully fetched {len(kb_components_data)} unique identified components.")
                collected_results['kb_components'] = kb_components_data
            else:
                logger.debug("No Identified Components found.")
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch KB Identified Scan Components: {e}")
            logger.warning(f"Failed to fetch KB components for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching KB Identified Scan Components: {e}")
            logger.warning(f"Unexpected error fetching KB components for {scan_code}", exc_info=True)

    # --- Fetch Scan File Metrics ---
    if should_fetch_metrics:
        try:
            logger.debug(f"\nFetching Scan File Metrics for '{scan_code}'...")
            scan_metrics_data = workbench.get_scan_folder_metrics(scan_code)
            if scan_metrics_data:
                logger.debug("Successfully fetched scan file metrics.")
                collected_results['scan_metrics'] = scan_metrics_data
            else:
                # Should not happen if API method raises error on failure/empty
                logger.debug("No scan file metrics data found or returned.")
        except (ApiError, NetworkError, ScanNotFoundError) as e:
            print(f"Warning: Could not fetch Scan File Metrics: {e}")
            logger.warning(f"Failed to fetch scan metrics for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching Scan File Metrics: {e}")
            logger.warning(f"Unexpected error fetching scan metrics for {scan_code}", exc_info=True)

    # --- Fetch Policy Warnings ---
    if should_fetch_policy:
        try:
            logger.debug(f"\nFetching Scan Policy Warnings Counter for '{scan_code}'...")
            # Use the counter method for summary display
            policy_warnings_data = workbench.get_policy_warnings_counter(scan_code)
            logger.debug("Successfully fetched policy warnings counter.")
            collected_results['policy_warnings'] = policy_warnings_data
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch Scan Policy Warnings: {e}")
            logger.warning(f"Failed to fetch policy warnings for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching Scan Policy Warnings: {e}")
            logger.warning(f"Unexpected error fetching policy warnings for {scan_code}", exc_info=True)

    # --- Fetch Vulnerabilities ---
    if should_fetch_vulnerabilities:
        try:
            logger.debug(f"\nFetching Vulnerabilities for '{scan_code}'...")
            vulnerabilities_data = workbench.list_vulnerabilities(scan_code)
            if vulnerabilities_data:
                logger.debug(f"Successfully fetched {len(vulnerabilities_data)} vulnerability entries.")
                collected_results['vulnerabilities'] = vulnerabilities_data
            else:
                logger.debug("No Vulnerabilities found or returned.")
        except (ApiError, NetworkError, ScanNotFoundError) as e:
            print(f"Warning: Could not fetch Vulnerabilities: {e}")
            logger.warning(f"Failed to fetch vulnerabilities for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching Vulnerabilities: {e}")
            logger.warning(f"Unexpected error fetching vulnerabilities for {scan_code}", exc_info=True)
            
    return collected_results

def _display_results(collected_results: Dict[str, Any], params: argparse.Namespace) -> bool:
    """
    Displays scan results based on the collected data and user preferences.
    
    Args:
        collected_results: Dictionary containing collected results
        params: Command-line parameters with display preferences
        
    Returns:
        bool: True if any data was displayed, False otherwise
    """
    # Get flags from parameters
    should_fetch_licenses = getattr(params, 'show_licenses', False)
    should_fetch_components = getattr(params, 'show_components', False)
    should_fetch_dependencies = getattr(params, 'show_dependencies', False)
    should_fetch_metrics = getattr(params, 'show_scan_metrics', False)
    should_fetch_policy = getattr(params, 'show_policy_warnings', False)
    should_fetch_vulnerabilities = getattr(params, 'show_vulnerabilities', False)
    
    # Get data from collected results
    da_results_data = collected_results.get('dependency_analysis')
    kb_licenses_data = collected_results.get('kb_licenses')
    kb_components_data = collected_results.get('kb_components')
    scan_metrics_data = collected_results.get('scan_metrics')
    policy_warnings_data = collected_results.get('policy_warnings')
    vulnerabilities_data = collected_results.get('vulnerabilities')
    
    print("\n--- Results Summary ---")
    displayed_something = False

    # Display Scan Metrics
    if should_fetch_metrics:
        print("\n=== Scan File Metrics ===")
        displayed_something = True
        if scan_metrics_data:
            total = scan_metrics_data.get('total', 'N/A')
            pending = scan_metrics_data.get('pending_identification', 'N/A')
            identified = scan_metrics_data.get('identified_files', 'N/A')
            no_match = scan_metrics_data.get('without_matches', 'N/A')
            print(f"  - Total Files Scanned: {total}")
            print(f"  - Files Pending Identification: {pending}")
            print(f"  - Files Identified: {identified}")
            print(f"  - Files Without Matches: {no_match}")
            print("-" * 25)
        else:
            print("Scan metrics data could not be fetched or was empty.")

    # Display Licenses
    if should_fetch_licenses:
        print("\n=== Identified Licenses ===")
        displayed_something = True
        kb_licenses_found = bool(kb_licenses_data)
        da_licenses_found = False

        if kb_licenses_found:
            print("Unique Licenses in Identified Components):")
            for lic in kb_licenses_data:
                identifier = lic.get('identifier', 'N/A')
                name = lic.get('name', 'N/A')
                print(f"  - {identifier}:{name}")
            print("-" * 25)

        if da_results_data:
            da_lic_names = sorted(list(set(
                comp.get('license_identifier', 'N/A') for comp in da_results_data if comp.get('license_identifier')
            )))
            # Check if any valid licenses were found in DA data
            if da_lic_names and any(lic != 'N/A' for lic in da_lic_names):
                print("Unique Licenses in Dependencies:")
                da_licenses_found = True
                for lic_name in da_lic_names:
                    if lic_name and lic_name != 'N/A':
                        print(f"  - {lic_name}")
                print("-" * 25)

        if not kb_licenses_found and not da_licenses_found:
            print("No Licenses to report.")

    # Display KB Components
    if should_fetch_components:
        print("\n=== Identified Components ===")
        displayed_something = True
        if kb_components_data:
            print("From Signature Scanning:")
            for comp in kb_components_data:
                print(f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')}")
            print("-" * 25)
        else:
            print("No KB Scan Components found to report.")

    # Display Dependencies
    if should_fetch_dependencies:
        print("\n=== Dependency Analysis Results ===")
        displayed_something = True
        if da_results_data:
            print("Component, Version, Scope, and License of Dependencies:")
            da_results_data.sort(key=lambda x: (x.get('name', '').lower(), x.get('version', '')))
            for comp in da_results_data:
                scopes_display = "N/A"
                scopes_str = comp.get("projects_and_scopes")
                if scopes_str:
                    try:
                        scopes_data = json.loads(scopes_str)
                        scopes_list = sorted(list(set(
                            p_info.get("scope") for p_info in scopes_data.values() if isinstance(p_info, dict) and p_info.get("scope")
                        )))
                        if scopes_list: scopes_display = ", ".join(scopes_list)
                    except (json.JSONDecodeError, AttributeError, TypeError) as scope_err:
                        logger.debug(f"Could not parse scopes for DA component {comp.get('name')}: {scope_err}")
                        pass
                print(f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')} "
                      f"(Scope: {scopes_display}, License: {comp.get('license_identifier', 'N/A')})")
            print("-" * 25)
        else:
            print("No Components found through Dependency Analysis.")

    # Display Policy Warnings
    if should_fetch_policy:
        print("\n=== Policy Warnings Summary ===")
        displayed_something = True
        if policy_warnings_data is not None:
            # Check if we have real data with non-zero values
            total_warnings = int(policy_warnings_data.get("policy_warnings_total", 0))
            files_with_warnings = int(policy_warnings_data.get("identified_files_with_warnings", 0))
            deps_with_warnings = int(policy_warnings_data.get("dependencies_with_warnings", 0))
            
            if total_warnings > 0:
                print(f"There are {total_warnings} policy warnings: "
                      f"{files_with_warnings} in Identified Files, and "
                      f"{deps_with_warnings} in Dependencies.")
            else:
                print("No policy warnings found.")
        else:
            print("Policy warnings counter data could not be fetched or was empty.")
        print("-" * 25)

    # Display Vulnerability Summary
    if should_fetch_vulnerabilities:
        print("\n=== Vulnerability Summary ===")
        displayed_something = True
        if vulnerabilities_data:
            num_cves = len(vulnerabilities_data)
            unique_components = set()
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

            for vuln in vulnerabilities_data:
                comp_name = vuln.get("component_name", "Unknown")
                comp_version = vuln.get("component_version", "Unknown")
                unique_components.add(f"{comp_name}:{comp_version}")
                severity = vuln.get("severity", "UNKNOWN").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            num_unique_components = len(unique_components)
            print(f"There are {num_cves} vulnerabilities affecting {num_unique_components} components.")
            print(f"By CVSS Score, "
                  f"{severity_counts['CRITICAL']} are Critical, "
                  f"{severity_counts['HIGH']} are High, "
                  f"{severity_counts['MEDIUM']} are Medium, and "
                  f"{severity_counts['LOW']} are Low.")

            if severity_counts['UNKNOWN'] > 0: print(f"  - Unknown:  {severity_counts['UNKNOWN']}")

        if vulnerabilities_data:
            print("\n=== Top Vulnerable Components ===")
            components_vulns = {}
            # Group vulnerabilities by component:version
            for vuln in vulnerabilities_data:
                comp_name = vuln.get("component_name", "UnknownComponent")
                comp_version = vuln.get("component_version", "UnknownVersion")
                comp_key = f"{comp_name}:{comp_version}"
                if comp_key not in components_vulns:
                    components_vulns[comp_key] = []
                components_vulns[comp_key].append(vuln)

            # Sort components by the number of vulnerabilities (descending)
            sorted_components = sorted(components_vulns.items(), key=lambda item: len(item[1]), reverse=True)

            # Define severity order for sorting vulnerabilities within each component
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

            for comp_key, vulns_list in sorted_components:
                print(f"\n{comp_key} - {len(vulns_list)} vulnerabilities")

                # Sort vulnerabilities within this component by severity
                sorted_vulns_list = sorted(
                    vulns_list,
                    key=lambda v: severity_order.get(v.get("severity", "UNKNOWN").upper(), 0),
                    reverse=True
                )

                # Display top 5 vulnerabilities for each component
                for i, vuln in enumerate(sorted_vulns_list[:5]):
                    severity = vuln.get("severity", "UNKNOWN").upper()
                    cve = vuln.get("cve", "NO_CVE_ID")
                    print(f"  - [{severity}] {cve}")
                if len(sorted_vulns_list) > 5:
                    print(f"  ... and {len(sorted_vulns_list) - 5} more.")
        else:
            print("No vulnerabilities found.")
        print("-" * 25)

    if not displayed_something:
        print("No results were successfully fetched or displayed for the specified flags.")
    print("------------------------------------")
    
    return displayed_something

def _save_results_to_file(filepath: str, results: Dict, scan_code: str):
    """Helper to save collected results dictionary to a JSON file."""
    output_dir = os.path.dirname(filepath) or "."
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Saved results to: {filepath}")
        logger.info(f"Saved results for scan '{scan_code}' to {filepath}")
    except (IOError, OSError) as e:
         logger.warning(f"Failed to save results to {filepath}: {e}")
         print(f"\nWarning: Failed to save results to {filepath}: {e}")
    except Exception as e:
         logger.warning(f"Unexpected error saving results to {filepath}: {e}", exc_info=True)
         print(f"\nWarning: Unexpected error saving results: {e}")

def _fetch_display_save_results(workbench: 'Workbench', params: argparse.Namespace, scan_code: str):
    """
    Fetches requested scan results, displays them, and optionally saves them to a file.
    This function orchestrates the fetch, display, and save operations.
    
    Args:
        workbench: The Workbench API client instance
        params: Command-line parameters
        scan_code: Scan code to fetch results for
    """
    # 1. Fetch the results
    # Check which results were requested *before* fetching
    any_results_requested = (
        getattr(params, 'show_licenses', False) or
        getattr(params, 'show_components', False) or
        getattr(params, 'show_dependencies', False) or
        getattr(params, 'show_scan_metrics', False) or
        getattr(params, 'show_policy_warnings', False) or
        getattr(params, 'show_vulnerabilities', False)
    )
    collected_results = _fetch_results(workbench, params, scan_code)
    
    # 2. Display the results
    if any_results_requested:
        _display_results(collected_results, params)
    
    # 3. Save the results if requested
    save_path = getattr(params, 'path_result', None)
    if save_path:
        if collected_results:
            print(f"\nSaving collected results to '{save_path}'...")
            _save_results_to_file(save_path, collected_results, scan_code)
        else:
            print("\nNo results were successfully collected, skipping save.")

# --- Report Saving ---
def _save_report_content(
    response_or_content: Union[requests.Response, str, bytes, dict, list],
    output_dir: str,
    report_scope: str,
    name_component: str,
    report_type: str
) -> None:
    """
    Saves report content (from response object or direct content) to a file.
    (Docstring omitted for brevity in this example, but should be kept)
    """
    if not output_dir:
        raise ValidationError("Output directory is not specified for saving report.")
    if not name_component:
        raise ValidationError("Name component (scan/project name) is not specified for saving report.")
    if not report_type:
        raise ValidationError("Report type is not specified for saving report.")

    filename = ""
    content_to_write: Union[str, bytes] = b""
    write_mode = 'wb'

    if isinstance(response_or_content, requests.Response):
        response = response_or_content

        # --- Always generate filename based on desired format ---
        safe_name = re.sub(r'[^\w\-]+', '_', name_component) # Allow letters, numbers, underscore, hyphen
        safe_scope = report_scope # Scope is already validated ('scan' or 'project')
        safe_type = re.sub(r'[^\w\-]+', '_', report_type)
        extension_map = {
            "xlsx": "xlsx", "spdx": "rdf", "spdx_lite": "xlsx",
            "cyclone_dx": "json", "html": "html", "dynamic_top_matched_components": "html",
            "string_match": "xlsx", "basic": "txt"
        }
        ext = extension_map.get(report_type.lower(), "txt") # Default to .txt if unknown
        filename = f"{safe_scope}-{safe_name}-{safe_type}.{ext}"
        logger.debug(f"Generated filename: {filename}")

        try:
            content_to_write = response.content
        except Exception as e:
            raise FileSystemError(f"Failed to read content from response object: {e}")

        content_type = response.headers.get('content-type', '').lower()
        if 'text' in content_type or 'json' in content_type or 'html' in content_type:
            write_mode = 'w'
            try:
                content_to_write = content_to_write.decode(response.encoding or 'utf-8', errors='replace')
            except Exception:
                 logger.warning(f"Could not decode response content as text, writing as binary. Content-Type: {content_type}")
                 write_mode = 'wb'
        else:
            write_mode = 'wb'

    elif isinstance(response_or_content, (dict, list)):
        # Handle direct JSON data (e.g., collected results)
        safe_name = re.sub(r'[^\w\-]+', '_', name_component)
        safe_scope = report_scope
        safe_type = re.sub(r'[^\w\-]+', '_', report_type) # Use report_type if available, else generic
        filename = f"{safe_scope}-{safe_name}-{safe_type}.json"
        try:
            content_to_write = json.dumps(response_or_content, indent=2)
            write_mode = 'w'
        except TypeError as e:
            raise ValidationError(f"Failed to serialize provided dictionary/list to JSON: {e}")
    elif isinstance(response_or_content, str):
        # Handle direct string content
        safe_name = re.sub(r'[^\w\-]+', '_', name_component)
        safe_scope = report_scope
        safe_type = re.sub(r'[^\w\-]+', '_', report_type)
        filename = f"{safe_scope}-{safe_name}-{safe_type}.txt"
        content_to_write = response_or_content
        write_mode = 'w'
    elif isinstance(response_or_content, bytes):
        # Handle direct bytes content
        safe_name = re.sub(r'[^\w\-]+', '_', name_component)
        safe_scope = report_scope
        safe_type = re.sub(r'[^\w\-]+', '_', report_type)
        filename = f"{safe_scope}-{safe_name}-{safe_type}.bin" # Generic binary extension
        content_to_write = response_or_content
        write_mode = 'wb'
    else:
        raise ValidationError(f"Unsupported content type for saving: {type(response_or_content)}")

    filepath = os.path.join(output_dir, filename)

    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create output directory '{output_dir}': {e}", exc_info=True)
        raise FileSystemError(f"Could not create output directory '{output_dir}': {e}") from e

    try:
        encoding_arg = {'encoding': 'utf-8'} if write_mode == 'w' else {}
        with open(filepath, write_mode, **encoding_arg) as f:
            f.write(content_to_write)
        print(f"Saved report to: {filepath}")
        logger.info(f"Successfully saved report to {filepath}")
    except IOError as e:
        logger.error(f"Failed to write report to {filepath}: {e}", exc_info=True)
        raise FileSystemError(f"Failed to write report to '{filepath}': {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error writing report to {filepath}: {e}", exc_info=True)
        raise FileSystemError(f"Unexpected error writing report to '{filepath}': {e}") from e
