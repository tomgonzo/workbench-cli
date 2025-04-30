# workbench_agent/handlers/show_results.py

import logging
import argparse

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _fetch_display_save_results
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
    print(f"\n--- Running Command: {params.command} ---")
    try:
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=False,
            params=params
        )

        print(f"\n--- Fetching Results for Scan '{scan_code}' (Project '{project_code}') ---")

        # --- Fetch, Display, and Save Results using the utility function ---
        _fetch_display_save_results(workbench, params, scan_code)

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError,
            ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})