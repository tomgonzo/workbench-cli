# workbench_cli/handlers/show_results.py

import logging
import argparse
from typing import TYPE_CHECKING

from ..utilities.error_handling import handler_error_wrapper
from ..utilities.scan_workflows import fetch_display_save_results
from ..exceptions import (
    ApiError,
    NetworkError,
    ValidationError,
    ProcessTimeoutError,
    ProcessError
)

if TYPE_CHECKING:
    from ..api import WorkbenchAPI

logger = logging.getLogger("workbench-cli")


@handler_error_wrapper
def handle_show_results(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'show-results' command. Fetches and displays results for an existing scan.
    
    Args:
        workbench: The Workbench API client
        params: Command line parameters
        
    Returns:
        bool: True if the operation was successful
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Validate that at least one show flag is provided
    show_flags = [
        params.show_licenses, params.show_components, params.show_dependencies,
        params.show_scan_metrics, params.show_policy_warnings, params.show_vulnerabilities
    ]
    if not any(show_flags):
        raise ValidationError("At least one '--show-*' flag must be provided to display results")
    
    # Resolve project and scan (find only)
    print("\nResolving scan for results display...")
    project_code = workbench.resolve_project(params.project_name, create_if_missing=False)
    scan_code, scan_id = workbench.resolve_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=False,
        params=params
    )
    
    # Wait for scan to complete before fetching results
    print("\nChecking scan completion status...")
    # This try/except block is necessary for the handler's logic to continue even if scan
    # status checking fails - we still want to attempt to show results
    try:
        # Check KB scan completion
        kb_scan_completed = False
        da_completed = False
        
        try:
            kb_status_data = workbench.get_scan_status("SCAN", scan_code)
            kb_scan_status = kb_status_data.get("status", "UNKNOWN").upper()
            kb_scan_completed = (kb_scan_status == "FINISHED")
        except Exception as e:
            logger.warning(f"Could not check KB scan status for '{scan_code}': {e}")
        
        # Check dependency analysis completion
        try:
            da_status_data = workbench.get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
            da_scan_status = da_status_data.get("status", "UNKNOWN").upper()
            da_completed = (da_scan_status == "FINISHED")
        except Exception as e:
            logger.debug(f"Could not check DA scan status for '{scan_code}': {e}")
            # DA might not be available for this scan, which is fine
        
        if not kb_scan_completed:
            print("\nWarning: The KB scan has not completed successfully. Results may be incomplete.")
            logger.warning(f"Showing results for scan '{scan_code}' that has not completed successfully.")
        
        # Dependency analysis might not be needed for all result types, so just warn
        if not da_completed and any([params.show_dependencies, params.show_vulnerabilities]):
            print("\nNote: Dependency Analysis has not completed. Dependency-related results may be incomplete.")
            logger.warning(f"Showing dependency results for scan '{scan_code}' without completed DA.")
            
    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        logger.warning(f"Could not verify scan completion for '{scan_code}': {e}. Proceeding anyway.")
        print("\nWarning: Could not verify scan completion status. Results may be incomplete.")
    
    # Fetch and display results
    print(f"\nFetching results for scan '{scan_code}'...")
    fetch_display_save_results(workbench, params, scan_code)
    
    return True
