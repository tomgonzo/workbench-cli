# workbench_cli/handlers/scan.py

import os
import time
import logging
import argparse
from typing import Dict, Any, TYPE_CHECKING

from ..utilities.error_handling import handler_error_wrapper
from ..utilities.scan_workflows import (
    ensure_scan_is_idle,
    fetch_display_save_results,
    print_operation_summary,
    determine_scans_to_run
)
from ..utilities.scan_target_validators import ensure_scan_compatibility, validate_reuse_source
from ..exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    FileSystemError,
    ValidationError,
    ProcessError,
    ProcessTimeoutError
)

if TYPE_CHECKING:
    from ..api import WorkbenchAPI

logger = logging.getLogger("workbench-cli")


@handler_error_wrapper
def handle_scan(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan' command. Uploads code, runs KB scan, optional DA, shows/saves results.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        bool: True if the operation completed successfully
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Initialize timing dictionary
    durations = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
        "extraction_duration": 0.0
    }
    
    # Validate scan parameters
    if not params.path:
        raise ValidationError("A path must be provided for the scan command.")
    if not os.path.exists(params.path):
        raise FileSystemError(f"The provided path does not exist: {params.path}")

    # Validate ID reuse source early - WARN if it cannot be validated
    api_reuse_type = None
    resolved_specific_code_for_reuse = None
    if getattr(params, 'id_reuse', False):
        print("\nValidating ID reuse source before proceeding...")
        try:
            api_reuse_type, resolved_specific_code_for_reuse = validate_reuse_source(workbench, params)
            print(f"Successfully validated ID reuse source.")
        except Exception as e:
            # Log the error but don't show additional warnings since validate_reuse_source already shows them
            logger.warning(f"ID reuse validation failed ({type(e).__name__}): {e}. Continuing without ID reuse.")
            # Disable ID reuse for this scan
            params.id_reuse = False

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

    # Assert scan is idle before uploading code
    print("\nEnsuring the Scan is idle before uploading code...")
    ensure_scan_is_idle(workbench, scan_code, params, ["SCAN", "DEPENDENCY_ANALYSIS"])

    # Clear existing scan content
    print("\nClearing existing scan content...")
    try:
        workbench.remove_uploaded_content(scan_code, "")
        print("Successfully cleared existing scan content.")
    except Exception as e:
        logger.warning(f"Failed to clear existing scan content: {e}")
        print(f"Warning: Could not clear existing scan content: {e}")
        print("Continuing with upload...")

    # Upload code to scan
    print("\nUploading Code to Workbench...")
    workbench.upload_scan_target(scan_code, params.path)
    print(f"Successfully uploaded {params.path} to Workbench.")

    # Handle archive extraction
    print("\nExtracting Uploaded Archive...")
    extraction_triggered = workbench.extract_archives(
        scan_code, params.recursively_extract_archives, params.jar_file_extraction
    )
    
    if extraction_triggered:
        if workbench._is_status_check_supported(scan_code, "EXTRACT_ARCHIVES"):
            try:
                extraction_status_data, extraction_duration = workbench.wait_for_archive_extraction(
                    scan_code,
                    params.scan_number_of_tries,
                    5
                )
                durations["extraction_duration"] = extraction_duration
            except Exception as e:
                logger.error(f"Archive extraction issue: {e}")
                print(f"\nWARNING: Archive extraction encountered an issue: {e}")
                print("Attempting to continue with the scan process...")
        else:
            print("Archive extraction status check not supported. Waiting 3 seconds before continuing...")
            time.sleep(3)
    else:
        print("No archives to extract. Continuing with scan...")

    # Verify scan can start
    ensure_scan_is_idle(workbench, scan_code, params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    
    # Determine which scan operations to run
    scan_operations = determine_scans_to_run(params)
    
    # Run KB Scan
    scan_completed = False
    da_completed = False
    
    # Handle dependency analysis only mode
    if not scan_operations["run_kb_scan"] and scan_operations["run_dependency_analysis"]:
        print("\nStarting Dependency Analysis only (skipping KB scan)...")
        workbench.start_dependency_analysis(scan_code, import_only=False)
        
        # Handle no-wait mode
        if getattr(params, 'no_wait', False):
            print("Dependency Analysis has been started.")
            print("\nExiting without waiting for completion (--no-wait mode).")
            print("You can check the status later using the 'show-results' command.")
            return True
        
        # Wait for dependency analysis to complete
        try:
            da_status_data, da_duration = workbench.wait_for_scan_to_finish(
                "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time
            )
            
            # Store the duration
            durations["dependency_analysis"] = da_duration
            da_completed = True
            
            # Show scan summary and operation details
            print_operation_summary(params, da_completed, project_code, scan_code, durations)
            
            # Show scan results if any were requested
            if any([params.show_licenses, params.show_components, params.show_dependencies,
                    params.show_scan_metrics, params.show_policy_warnings, params.show_vulnerabilities]):
                fetch_display_save_results(workbench, params, scan_code)
            
            return True
            
        except Exception as e:
            logger.error(f"Error waiting for dependency analysis to complete: {e}", exc_info=True)
            print(f"\nError: Dependency analysis failed: {e}")
            return False
    
    # Start the KB scan (only if run_kb_scan is True)
    if scan_operations["run_kb_scan"]:
        print("\nStarting KB Scan Process...")
        workbench.run_scan(
            scan_code,
            params.limit,
            params.sensitivity,
            params.autoid_file_licenses,
            params.autoid_file_copyrights,
            params.autoid_pending_ids,
            params.delta_scan,
            params.id_reuse,
            api_reuse_type if params.id_reuse else None,
            resolved_specific_code_for_reuse if params.id_reuse else None,
            run_dependency_analysis=scan_operations["run_dependency_analysis"]
        )
        
        # Check if we should wait for completion
        if getattr(params, 'no_wait', False):
            print("\nKB Scan started successfully.")
            
            if scan_operations["run_dependency_analysis"]:
                print("Dependency Analysis will automatically start after scan completion.")
                
            print("\nExiting without waiting for completion (--no-wait mode).")
            print("You can check the scan status later using the 'show-results' command.")
            return True
        else:
            # Wait for KB scan to finish
            kb_status_data, kb_duration = workbench.wait_for_scan_to_finish(
                "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
            )
            
            # Store the duration in the durations dictionary
            durations["kb_scan"] = kb_duration
            scan_completed = True
            
            # If dependency analysis was requested, wait for it to complete
            if scan_completed and scan_operations["run_dependency_analysis"]:
                print("\nWaiting for Dependency Analysis to complete...")
                try:
                    da_status_data, da_duration = workbench.wait_for_scan_to_finish(
                        "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time,
                    )
                    
                    # Store the duration
                    durations["dependency_analysis"] = da_duration
                    da_completed = True
                except Exception as e:
                    logger.warning(f"Error waiting for dependency analysis to complete: {e}")
                    print(f"\nWarning: Error waiting for dependency analysis to complete: {e}")
                    da_completed = False
        
        # Show scan summary and operation details
        print_operation_summary(params, da_completed, project_code, scan_code, durations)
        
        # Show scan results if any were requested
        if any([params.show_licenses, params.show_components, params.show_dependencies,
                params.show_scan_metrics, params.show_policy_warnings, params.show_vulnerabilities]):
            fetch_display_save_results(workbench, params, scan_code)
        
        return True
