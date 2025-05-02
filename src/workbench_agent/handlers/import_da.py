# workbench_agent/handlers/import_da.py

import os
import time
import logging
import argparse
from typing import Dict, List, Optional, Union, Any, Tuple

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _fetch_display_save_results,
    handler_error_wrapper
)
from ..exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    FileSystemError,
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
def handle_import_da(workbench: Workbench, params: argparse.Namespace) -> bool:
    """
    Handler for the 'import-da' command. Imports Dependency Analysis results from a file.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        bool: True if the operation completed successfully
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Validate scan parameters
    if not params.path:
        raise ValidationError("A path must be provided for the import-da command.")
    if not os.path.exists(params.path):
        raise FileSystemError(f"The provided path does not exist: {params.path}")
    if not os.path.isfile(params.path):
        raise ValidationError(f"The provided path must be a file: {params.path}")

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

    # Assert scan is idle before uploading code to a file that will be marked as DA file
    print("\nUploading DA Results to Workbench...")
    workbench.upload_files(scan_code, params.path, is_da_import=True)
    print(f"Successfully uploaded {params.path} to Workbench.")

    # Import DA results
    print("\nImporting Dependency Analysis Results...")
    workbench.start_dependency_analysis(scan_code, import_only=True)
    print("Import started. Waiting for import to complete...")
    
    # Wait for DA to finish
    workbench.wait_for_scan_to_finish(
        "DEPENDENCY_ANALYSIS", 
        scan_code, 
        params.scan_number_of_tries, 
        # Use a shorter interval for dependency analysis import since it typically
        # finishes much faster than regular scans (2s instead of default 30s)
        2
    )
    print("Dependency Analysis import has completed.")
    
    # Fetch and display results
    print("\nFetching and displaying results...")
    _fetch_display_save_results(workbench, params, scan_code)
    
    return True