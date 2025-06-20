# workbench_cli/handlers/import_da.py

import logging
import argparse
import os
from typing import TYPE_CHECKING, Dict
from ..utilities.error_handling import handler_error_wrapper
from ..exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ValidationError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    FileSystemError,
)
from ..utilities.scan_workflows import (
    ensure_scan_is_idle, 
    wait_for_scan_completion, 
    print_operation_summary,
    fetch_display_save_results
)
from ..utilities.scan_target_validators import ensure_scan_compatibility

if TYPE_CHECKING:
    from ..api import WorkbenchAPI

logger = logging.getLogger("workbench-cli")

def _get_project_and_scan_codes(workbench: "WorkbenchAPI", params: argparse.Namespace) -> tuple[str, str]:
    """
    Resolve project and scan codes for dependency analysis import.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        tuple[str, str]: Project code and scan code
    """
    project_code = workbench.resolve_project(params.project_name, create_if_missing=True)
    scan_code, _ = workbench.resolve_scan(params.scan_name, params.project_name, create_if_missing=True, params=params)
    return project_code, scan_code

@handler_error_wrapper
def handle_import_da(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'import-da' command. Imports dependency analysis data from a file.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        bool: True if the operation completed successfully
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Initialize timing dictionary
    durations = {
        "dependency_analysis": 0.0
    }
    
    # Validate scan parameters - CRITICAL: Match old implementation
    if not params.path:
        raise ValidationError("A path must be provided for the import-da command.")
    if not os.path.exists(params.path):
        raise FileSystemError(f"The provided path does not exist: {params.path}")
    if not os.path.isfile(params.path):
        raise ValidationError(f"The provided path must be a file: {params.path}")
    
    # Resolve project and scan (find or create)
    print("\nChecking if the Project and Scan exist or need to be created...")
    project_code, scan_code = _get_project_and_scan_codes(workbench, params)
    
    print(f"Processing dependency analysis import for scan '{scan_code}' in project '{project_code}'...")
    print(f"Importing from: {params.path}")

    # Ensure scan is compatible with the current operation
    ensure_scan_compatibility(workbench, params, scan_code)

    # Ensure scan is idle before starting dependency analysis import
    print("\nEnsuring the Scan is idle before starting dependency analysis import...")
    ensure_scan_is_idle(workbench, scan_code, params, ["DEPENDENCY_ANALYSIS"])

    # Upload dependency analysis file
    print("\n--- Uploading Dependency Analysis File ---")
    try:
        workbench.upload_dependency_analysis_results(scan_code=scan_code, path=params.path)
        print(f"Dependency analysis file uploaded successfully from: {params.path}")
    except Exception as e:
        logger.error(f"Failed to upload dependency analysis file for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchCLIError(f"Failed to upload dependency analysis file: {e}", details={"error": str(e)}) from e

    # Start dependency analysis import
    print("\n--- Starting Dependency Analysis Import ---")
    
    # Verify DA import can start - CRITICAL: Match old implementation  
    print("Verifying Dependency Analysis can start...")
    try:
        workbench.ensure_process_can_start(
            "DEPENDENCY_ANALYSIS",
            scan_code,
            wait_max_tries=params.scan_number_of_tries,
            wait_interval=params.scan_wait_time
        )
    except Exception as e:
        logger.error(f"Cannot start dependency analysis import for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchCLIError(f"Cannot start dependency analysis import: {e}", details={"error": str(e)}) from e
        
    try:
        workbench.start_dependency_analysis(scan_code=scan_code, import_only=True)
        print("Dependency analysis import initiated successfully.")
    except Exception as e:
        logger.error(f"Failed to start dependency analysis import for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchCLIError(f"Failed to start dependency analysis import: {e}", details={"error": str(e)}) from e

    # Handle no-wait mode
    if getattr(params, 'no_wait', False):
        print("\nDependency Analysis import started successfully.")
        print("\nExiting without waiting for completion (--no-wait mode).")
        print("You can check the status later using the 'show-results' command.")
        
        # Print operation summary for no-wait mode
        print_operation_summary(params, True, project_code, scan_code, durations)
        return True

    # Wait for dependency analysis to complete  
    da_completed = False
    try:
        print("\nWaiting for Dependency Analysis import to complete...")
        # Use optimized 2-second wait interval for import-only mode (matches old implementation)
        da_status_data, da_duration = workbench.wait_for_scan_to_finish(
            "DEPENDENCY_ANALYSIS", 
            scan_code, 
            params.scan_number_of_tries, 
            2  # Use 2-second wait interval for import-only mode as it finishes faster
        )
        
        # Store the DA import duration
        durations["dependency_analysis"] = da_duration
        da_completed = True
        
        print("Dependency Analysis import completed successfully.")
            
    except (ProcessTimeoutError, ProcessError) as e:
        logger.error(f"Error during dependency analysis import for '{scan_code}': {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error during dependency analysis import for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchCLIError(f"Error during dependency analysis import: {e}", details={"error": str(e)}) from e

    # Print operation summary
    print_operation_summary(params, da_completed, project_code, scan_code, durations)

    # Fetch and display results - CRITICAL: Match old implementation behavior
    if da_completed:
        print("\n--- Fetching Results ---")
        try:
            fetch_display_save_results(workbench, params, scan_code)
        except Exception as e:
            logger.warning(f"Failed to fetch and display results: {e}")
            print(f"Warning: Failed to fetch and display results: {e}")
    
    return da_completed
