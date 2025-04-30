# workbench_agent/handlers/scan_git.py

import logging
import argparse
from typing import Dict, List, Optional, Union, Any

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _execute_standard_scan_flow
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
    print(f"\n--- Running {params.command} Command ---")
    try:
        if not params.git_url:
            raise ValidationError("Git URL is required for scan-git command")

        project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        ref_display = f"branch: {params.git_branch}" if params.git_branch else f"tag: {params.git_tag}"
        print(f"\nCloning from Git: {params.git_url} ({ref_display}) for scan '{scan_code}'")

        try:
            payload_dl = {
                "group": "scans",
                "action": "download_content_from_git",
                "data": {"scan_code": scan_code}
            }
            response_dl = workbench._send_request(payload_dl)
            if response_dl.get("status") != "1":
                raise ApiError(f"Failed to initiate download from Git: {response_dl.get('error', 'Unknown error')}",
                             details=response_dl)
            logger.debug("Successfully started Git Clone.")
        except (ApiError, NetworkError) as e:
            raise WorkbenchAgentError(f"Failed to initiate Git clone: {e}", details=getattr(e, 'details', None))
        except Exception as e:
            logger.error(f"Unexpected error initiating Git clone for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during Git clone initiation: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        print("\nWaiting for Git Clone to complete...")
        try:
            workbench._wait_for_process(
                process_description=f"Git Clone for scan '{scan_code}'",
                check_function=workbench._send_request,
                check_args={
                    "payload": {
                        "group": "scans",
                        "action": "check_status_download_content_from_git",
                        "data": {"scan_code": scan_code}
                    }
                },
                status_accessor=lambda response: response.get("data", "UNKNOWN"),
                success_values={"FINISHED"},
                failure_values={"FAILED", "ERROR"},
                max_tries=params.scan_number_of_tries,
                wait_interval=10,
                progress_indicator=True
            )

            print("Git Clone completed.")
        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            raise
        except Exception as e:
            logger.error(f"Unexpected error waiting for Git clone for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during Git clone waiting: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        # Execute the main scan flow
        # _execute_standard_scan_flow now handles results internally via _fetch_display_save_results
        _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError,
            ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})