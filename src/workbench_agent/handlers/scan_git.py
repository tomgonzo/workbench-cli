# workbench_agent/handlers/scan_git.py

import time
import logging
import argparse
from typing import Dict, List, Optional, Union, Any, Tuple

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _execute_standard_scan_flow,
    _fetch_display_save_results,
    _assert_scan_is_idle,
    _validate_reuse_source,
    handler_error_wrapper
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


@handler_error_wrapper
def handle_scan_git(workbench: Workbench, params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan-git' command. Triggers a scan on code directly from Git.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        bool: True if the operation completed successfully
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Validate ID reuse source early to avoid cloning repository if reuse source doesn't exist
    if getattr(params, 'id_reuse', False):
        print("\nValidating ID reuse source before proceeding...")
        api_reuse_type, resolved_specific_code_for_reuse = _validate_reuse_source(workbench, params)
        # Store these values in params for later use during the scan process
        params.api_reuse_type = api_reuse_type
        params.resolved_specific_code_for_reuse = resolved_specific_code_for_reuse
    
    # Resolve project and scan (find or create)
    print("\nChecking if the Project and Scan exist or need to be created...")
    project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
    scan_code, scan_id = _resolve_scan(
        workbench,
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=True,
        params=params
    )

    # Assert scan is idle before triggering Git clone
    print("\nEnsuring the Scan is idle before triggering Git clone...")
    _assert_scan_is_idle(workbench, scan_code, params, ["SCAN", "DEPENDENCY_ANALYSIS", "GIT_CLONE"])

    # Trigger Git clone
    print(f"\nTriggering Git clone for repository '{params.git_url}'...")
    git_ref_type = "tag" if params.git_tag else ("commit" if params.git_commit else "branch")
    git_ref_value = params.git_tag or params.git_commit or params.git_branch
    print(f"Using {git_ref_type} '{git_ref_value}'...")
    
    # Download content from Git
    workbench.download_content_from_git(scan_code)
    print("Git clone initiated successfully. Waiting for clone to complete...")
    workbench.wait_for_git_clone(scan_code, params.scan_number_of_tries, params.scan_wait_time)
    print(f"Successfully cloned Git repository from {params.git_url}")

    # Execute the main scan flow (KB Scan -> Wait -> Optional DA -> Wait -> Summary)
    print("\nStarting the Scan Process...")
    scan_completed, da_completed, _ = _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)
    
    # Fetch and display results if scan completed successfully
    if scan_completed or da_completed:
        logger.debug("\nFetching and Displaying Results...")
        _fetch_display_save_results(workbench, params, scan_code)
    else:
        print("\nSkipping result fetching since scan did not complete successfully.")
    return scan_completed or da_completed