# workbench_agent/handlers/show_results.py

import logging
import argparse

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _fetch_display_save_results,
    _wait_for_scan_completion
)
from ..exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProcessError,
    ProcessTimeoutError
)

# Get logger
logger = logging.getLogger("log")

def handle_show_results(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'show-results' command. Fetches, displays, and saves results for an existing scan.
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    try:
        # Ensure required parameters have default values
        if not hasattr(params, 'scan_number_of_tries'):
            params.scan_number_of_tries = 60  # Default value
        if not hasattr(params, 'scan_wait_time'):
            params.scan_wait_time = 5  # Default value in seconds
            
        # Resolve project and scan
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=False,
            params=params
        )

        print(f"\n--- Processing Results for Scan '{scan_code}' (Project '{project_code}') ---")
        
        # Wait for KB scan and DA to complete before showing results
        scan_completed, da_completed, durations = _wait_for_scan_completion(workbench, params, scan_code)
        
        if not scan_completed:
            raise ProcessError("Cannot show results because the scan has not completed successfully.")
        
        # --- Fetch, Display, and Save Results using the utility function ---
        _fetch_display_save_results(workbench, params, scan_code)

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError,
            ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})