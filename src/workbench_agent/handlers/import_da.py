# workbench_agent/handlers/import_da.py

import os
import logging
import argparse

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _print_operation_summary,
    _fetch_display_save_results
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

def handle_import_da(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'import-da' command. Uploads DA results, runs import, shows/saves results.
    """
    print(f"\n--- Running Command: {params.command} ---")
    try:
        if not params.path:
            raise ValidationError("Path to DA results file is required for import-da command")
        if not os.path.isfile(params.path):
            raise FileSystemError(f"DA results path is not a valid file: {params.path}")

        project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        print(f"\nUploading DA Results File: {params.path} for scan '{scan_code}'...")
        try:
            workbench.upload_files(scan_code, params.path, is_da_import=True)
            print("DA results file upload initiated.")
        except FileSystemError as e:
            raise FileSystemError(f"Failed to upload DA results file '{params.path}': {e}", details=getattr(e, 'details', None))
        except (ApiError, NetworkError) as e:
            raise WorkbenchAgentError(f"Error during DA results file upload from '{params.path}': {e}", details=getattr(e, 'details', None))
        except Exception as e:
            logger.error(f"Unexpected error during DA results upload from '{params.path}' for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during DA results file upload: {e}",
                                    details={"error": str(e), "path": params.path, "scan_code": scan_code})

        print("\nStarting DA Import process...")
        da_completed = False # Initialize here
        try:
            workbench.start_dependency_analysis(scan_code, import_only=True)
            workbench.wait_for_scan_to_finish(
                "DEPENDENCY_ANALYSIS",
                scan_code,
                params.scan_number_of_tries,
                params.scan_wait_time
            )
            print("DA Import process complete.")
            da_completed = True

        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError, ScanNotFoundError) as e:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during DA import for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during DA import: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        # --- Print Summary ---
        _print_operation_summary(params, da_completed, project_code, scan_code)

        # --- Fetch, Display, and Save Results using the utility function ---
        _fetch_display_save_results(workbench, params, scan_code)

    except (ProjectNotFoundError, ScanNotFoundError, FileSystemError, ApiError,
            NetworkError, ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})