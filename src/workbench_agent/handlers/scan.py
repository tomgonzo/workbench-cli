# workbench_agent/handlers/scan.py

import os
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
    _assert_scan_is_idle
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


def handle_scan(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'scan' command. Uploads code, runs KB scan, optional DA, shows/saves results.
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    try:
        # Validate scan parameters
        if not params.path:
            raise ValidationError("A path must be provided for the scan command.")
        if not os.path.exists(params.path):
            raise FileSystemError(f"The provided path does not exist: {params.path}")

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

        # Assert scan is idle before uploading code
        print("\nAsserting scan is idle before uploading code...")
        _assert_scan_is_idle(workbench, scan_code, params, ["SCAN", "DEPENDENCY_ANALYSIS"])

        print("\nUploading Code to Workbench...")
        try:
            workbench.upload_files(scan_code, params.path, is_da_import=False)
            print(f"Successfully uploaded {params.path} to Workbench.")
        except FileSystemError as e:
            raise FileSystemError(f"Failed to upload files from '{params.path}': {e}", details=getattr(e, 'details', None))
        except (ApiError, NetworkError) as e:
            raise WorkbenchAgentError(f"Error during file upload from '{params.path}': {e}", details=getattr(e, 'details', None))
        except Exception as e:
            logger.error(f"Unexpected error during file upload from '{params.path}' for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during file upload: {e}",
                                    details={"error": str(e), "path": params.path, "scan_code": scan_code})

        print("\nExtracting Uploaded Archive...")
        try:
            extraction_triggered = workbench.extract_archives(
                scan_code, params.recursively_extract_archives, params.jar_file_extraction
            )
            if extraction_triggered:
                if workbench._is_status_check_supported(scan_code, "EXTRACT_ARCHIVES"):
                    print("Waiting for archive extraction to complete (using check_status)...")
                    workbench.wait_for_archive_extraction(
                        scan_code,
                        params.scan_number_of_tries,
                        5
                    )
                    print("Archive extraction completed.")
                else:
                    print("Consider upgrading to 25.1 to support checking the status of archive extraction.")
                    print("Waiting 5 seconds before starting KB scan...")
                    time.sleep(5)
            else:
                 print("Archive extraction was not triggered (possibly no archives or API indicated completion immediately).")

        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during archive extraction for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during archive extraction: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        # Execute the main scan flow (KB Scan -> Wait -> Optional DA -> Wait -> Summary)
        print("\nStarting the Scan Process...")
        scan_completed, da_completed = _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)
        
        # Fetch and display results if scan completed successfully
        if scan_completed or da_completed:
            logger.debug("\nFetching and Displaying Results...")
            _fetch_display_save_results(workbench, params, scan_code)
        else:
            print("\nSkipping result fetching since scan did not complete successfully.")

    except (ProjectNotFoundError, ScanNotFoundError, FileSystemError, ApiError,
            NetworkError, ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})