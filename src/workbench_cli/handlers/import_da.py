# workbench_cli/handlers/import_da.py

import os
import logging
import argparse

from ..api import WorkbenchAPI
from ..utils import (
    _assert_scan_is_idle,
    _fetch_display_save_results,
    handler_error_wrapper,
    _wait_for_scan_completion,
    _print_operation_summary
)
from ..utilities.scan_target_validators import ensure_scan_compatibility
from ..exceptions import (
    FileSystemError,
    ValidationError,
    ProcessError,
    ProcessTimeoutError
)

# Get logger from the handlers package
from . import logger

@handler_error_wrapper
def handle_import_da(workbench: WorkbenchAPI, params: argparse.Namespace) -> bool:
    """
    Handler for the 'import-da' command. Imports Dependency Analysis results from a file.
    
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
    
    # Validate scan parameters
    if not params.path:
        raise ValidationError("A path must be provided for the import-da command.")
    if not os.path.exists(params.path):
        raise FileSystemError(f"The provided path does not exist: {params.path}")
    if not os.path.isfile(params.path):
        raise ValidationError(f"The provided path must be a file: {params.path}")

    # Resolve project and scan (find or create)
    print("\nChecking if the Project and Scan exist or need to be created...")
    project_code = workbench.resolve_project(params.project_name, create_if_missing=True)
    scan_code, scan_id = workbench.resolve_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=True,
        params=params
    )

    # Ensure scan is compatible with the current operation
    ensure_scan_compatibility(workbench, params, scan_code)

    # Assert scan is idle before uploading
    print("\nEnsuring the Scan is idle before uploading DA file...")
    _assert_scan_is_idle(workbench, scan_code, params, ["DEPENDENCY_ANALYSIS"])

    # Upload DA file
    print("\nUploading DA Results to Workbench...")
    workbench.upload_files(scan_code, params.path, is_da_import=True)
    print(f"Successfully uploaded {params.path} to Workbench.")

    # Import DA results
    print("\nImporting Dependency Analysis Results...")
    
    # Verify DA import can start
    workbench.assert_process_can_start(
        "DEPENDENCY_ANALYSIS",
        scan_code,
        params.scan_number_of_tries,
        params.scan_wait_time
    )
    
    # Start the DA import
    workbench.start_dependency_analysis(scan_code, import_only=True)
    print("Import started. Waiting for import to complete...")
    
    # Wait for DA to finish - use 2-second wait interval for import-only mode as it finishes faster
    da_status_data, da_duration = workbench.wait_for_scan_to_finish(
        "DEPENDENCY_ANALYSIS", 
        scan_code, 
        params.scan_number_of_tries, 
        2  # Use 2-second wait interval for import-only mode as it finishes faster
    )
    
    # Store the DA import duration
    durations["dependency_analysis"] = da_duration
    
    print("Dependency Analysis import has completed successfully.")
    
    # Print operation summary
    _print_operation_summary(params, True, project_code, scan_code, durations)
    
    # Fetch and display results
    _fetch_display_save_results(workbench, params, scan_code)
    
    return True
