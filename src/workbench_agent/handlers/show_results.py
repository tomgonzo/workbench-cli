# workbench_agent/handlers/show_results.py

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
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError
)

# Get logger
logger = logging.getLogger("log")


@handler_error_wrapper
def handle_show_results(workbench: Workbench, params: argparse.Namespace) -> bool:
    """
    Handler for the 'show-results' command. Fetches and displays results for an existing scan.
    
    Args:
        workbench: The Workbench API client
        params: Command line parameters
        
    Returns:
        bool: True if the operation was successful
        
    Raises:
        Various exceptions based on errors that occur during the process
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
    
    # Fetch and display results
    print(f"\nFetching results for scan '{scan_code}'...")
    _fetch_display_save_results(workbench, params, scan_code)
    
    return True