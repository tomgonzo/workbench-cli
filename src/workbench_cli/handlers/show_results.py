# workbench_cli/handlers/show_results.py

import logging
import argparse

from ..api import WorkbenchAPI
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _fetch_display_save_results,
    _wait_for_scan_completion,
    handler_error_wrapper
)
from ..exceptions import (
    ApiError,
    NetworkError,
    ValidationError,
    ProcessTimeoutError,
    ProcessError
)

# Get logger from the handlers package
from . import logger


@handler_error_wrapper
def handle_show_results(workbench: WorkbenchAPI, params: argparse.Namespace) -> bool:
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
    project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
    scan_code, scan_id = _resolve_scan(
        workbench,
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
        kb_scan_completed, da_completed, _ = _wait_for_scan_completion(workbench, params, scan_code)
        
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
    _fetch_display_save_results(workbench, params, scan_code)
    
    return True
