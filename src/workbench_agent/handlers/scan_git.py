# workbench_agent/handlers/scan_git.py

import logging
import argparse
from typing import Dict, List, Optional, Union, Any, Tuple

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _execute_standard_scan_flow,
    _fetch_display_save_results,
    _assert_scan_is_idle
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

def handle_scan_git(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'scan-git' command. Clones repo, runs KB scan, optional DA, shows/saves results.
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    try:
        if not params.git_url:
            raise ValidationError("Git URL is required for scan-git command")
        
        print("\nChecking if the Project and Scan exist or need to be created...")
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        # Assert scan is idle before initiating Git clone
        print("\nEnsuring the scan is idle before initiating Git clone...")
        _assert_scan_is_idle(workbench, scan_code, params, ["SCAN", "DEPENDENCY_ANALYSIS", "GIT_CLONE"])

        ref_display = f"branch: {params.git_branch}" if params.git_branch else f"tag: {params.git_tag}"
        print(f"\nInitiating clone from Git: {params.git_url} ({ref_display})")

        try:
            workbench.download_content_from_git(scan_code)
        except (ApiError, NetworkError) as e:
            raise WorkbenchAgentError(f"Failed to initiate Git clone: {e}", details=getattr(e, 'details', None))
        except Exception as e:
            logger.error(f"Unexpected error initiating Git clone for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during Git clone initiation: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        try:
            workbench.wait_for_git_clone(scan_code, params.scan_number_of_tries, 10)
        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            raise
        except Exception as e:
            logger.error(f"Unexpected error waiting for Git clone for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during Git clone waiting: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        # Execute the main scan flow
        print("\nStarting the Scan Process...")
        scan_completed, da_completed = _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)
        
        # Fetch and display results if scan completed successfully
        if scan_completed:
            print("\nFetching and Displaying Results...")
            _fetch_display_save_results(workbench, params, scan_code)
        else:
            print("\nSkipping result fetching since scan did not complete successfully.")

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError,
            ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})