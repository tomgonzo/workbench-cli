# workbench_cli/handlers/scan_git.py

import logging
import argparse
from typing import Dict

from ..api import WorkbenchAPI
from ..utils import (
    _fetch_display_save_results,
    _assert_scan_is_idle,
    _wait_for_scan_completion,
    _print_operation_summary,
    handler_error_wrapper,
    determine_scans_to_run
)
from ..utilities.scan_target_validators import ensure_scan_compatibility, validate_reuse_source
from ..exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ValidationError,
    ProcessError,
    ProcessTimeoutError
)

# Get logger from the handlers package
from . import logger


@handler_error_wrapper
def handle_scan_git(workbench: WorkbenchAPI, params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan-git' command. Triggers a scan on code directly from Git.
    
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
        "git_clone": 0.0
    }
    
    # Validate ID reuse source early to WARN if it cannot be validated
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

    # Assert scan is idle before triggering Git clone
    print("\nEnsuring the Scan is idle before triggering Git clone...")
    _assert_scan_is_idle(workbench, scan_code, params, ["SCAN", "DEPENDENCY_ANALYSIS", "GIT_CLONE"])

    # Trigger Git clone
    git_ref_type = "tag" if params.git_tag else ("commit" if params.git_commit else "branch")
    git_ref_value = params.git_tag or params.git_commit or params.git_branch
    print(f"\nCloning the '{params.git_url}' repository using {git_ref_type}: '{git_ref_value}'.")
    
    # Download content from Git
    workbench.download_content_from_git(scan_code)
    git_status_data, git_duration = workbench.wait_for_git_clone(scan_code, params.scan_number_of_tries, params.scan_wait_time)
    # Store git clone duration
    durations["git_clone"] = git_duration
    print(f"\nSuccessfully cloned Git repository from {params.git_url}")
    
    # Remove .git directory before starting scan
    print("\nRemoving .git directory to optimize scan...")
    try:
        if workbench.remove_uploaded_content(scan_code, ".git/"):
            print("Successfully removed .git directory.")
    except Exception as e:
        logger.warning(f"Error removing .git directory: {e}. Continuing with scan...")
        print(f"Warning: Error removing .git directory: {e}. Continuing with scan...")

    # Run KB Scan
    scan_completed = False
    da_completed = False
    
    try:
        # Verify scan can start
        workbench.assert_process_can_start(
            "SCAN",
            scan_code,
            params.scan_number_of_tries,
            params.scan_wait_time
        )
        
        # Determine which scan operations to run
        scan_operations = determine_scans_to_run(params)
        
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
                
                # We didn't run a KB scan but we'll mark it as completed for result processing
                scan_completed = True
                
                # Print operation summary
                _print_operation_summary(params, da_completed, project_code, scan_code, durations)
                
                # Show results
                _fetch_display_save_results(workbench, params, scan_code)
                
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
            
            # Check if no-wait mode is enabled - if so, exit early
            if getattr(params, 'no_wait', False):
                print("\nKB Scan started successfully.")
                if scan_operations["run_dependency_analysis"]:
                    print("Dependency Analysis will automatically start after scan completion.")
                
                print("\nExiting without waiting for completion (--no-wait mode).")
                print("You can check the scan status later using the 'show-results' command.")
                return True
            else:
                # Wait for KB scan to finish and get duration
                kb_status_data, kb_duration = workbench.wait_for_scan_to_finish(
                    "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
                )
                
                # Record KB scan duration
                durations["kb_scan"] = kb_duration
                scan_completed = True
                
                # If dependency analysis was requested, wait for it to complete
                if scan_completed and scan_operations["run_dependency_analysis"]:
                    print("\nWaiting for Dependency Analysis to complete...")
                    try:
                        da_status_data, da_duration = workbench.wait_for_scan_to_finish(
                            "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time,
                        )
                        
                        # Record DA duration
                        durations["dependency_analysis"] = da_duration
                        da_completed = True
                    except Exception as e:
                        logger.warning(f"Error waiting for dependency analysis to complete: {e}")
                        print(f"\nWarning: Error waiting for dependency analysis to complete: {e}")
                        da_completed = False
    
    except (ProcessTimeoutError, ProcessError) as e:
        scan_completed = False
        raise
    except Exception as e:
        scan_completed = False
        logger.error(f"Error during KB scan for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchCLIError(f"Error during KB scan: {e}", details={"error": str(e)}) from e

    # Process completed operations
    if scan_completed:
        # Print operation summary
        _print_operation_summary(params, da_completed, project_code, scan_code, durations)

        # Check for pending files (informational)
        try:
            pending_files = workbench.get_pending_files(scan_code)
            if pending_files:
                print(f"\nNote: {len(pending_files)} files are Pending Identification.")
            else:
                print("\nNote: No files are Pending Identification.")
        except Exception as e:
            logger.warning(f"Could not retrieve pending file count: {e}")
            print(f"\nWarning: Could not retrieve pending file count: {e}")
    
    # Fetch and display results if scan completed successfully
    if scan_completed or da_completed:
        _fetch_display_save_results(workbench, params, scan_code)
    else:
        print("\nSkipping result fetching since scan did not complete successfully.")
    
    return scan_completed or da_completed
