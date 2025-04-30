# workbench_agent/handlers/evaluate_gates.py

import logging
import argparse

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan
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


def handle_evaluate_gates(workbench: Workbench, params: argparse.Namespace) -> bool:
    """
    Handler for the 'evaluate-gates' command. Checks scan status, pending files,
    and policy violations. Sets exit code based on --fail-on flag.

    Returns:
        bool: True if gate checks pass according to --fail-on, False otherwise.
    """
    print(f"\n--- Running Command: {params.command} ---")
    # Initialize check results
    found_pending = False
    found_policy_violations = False
    pending_files_details = {}
    policy_violations_details = []
    api_check_error = False # Flag if checks couldn't be performed

    try:
        # --- Resolve Project and Scan ---
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=False,
            params=params
        )

        print(f"\nEvaluating gates for scan '{scan_code}' (Project: '{project_code}')...")

        # --- 1. Check Scan Completion Status ---
        print("\nChecking KB Scan status...")
        try:
             kb_status_data = workbench.get_scan_status("SCAN", scan_code)
             kb_status = kb_status_data.get("progress_state", "UNKNOWN").upper()
             print(f"Current KB Scan status: {kb_status}")
             if kb_status not in {"FINISHED", "FAILED", "CANCELLED"}:
                 print("KB Scan is not finished. Waiting...")
                 workbench.wait_for_scan_to_finish(
                     "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
                 )
                 print("KB Scan finished.")
                 # Re-check status after waiting
                 kb_status_data = workbench.get_scan_status("SCAN", scan_code)
                 kb_status = kb_status_data.get("progress_state", "UNKNOWN").upper()

             if kb_status in {"FAILED", "CANCELLED"}:
                  print(f"Error: KB Scan {kb_status}. Cannot evaluate gates.")
                  # If scan itself failed, the gates implicitly fail regardless of --fail-on
                  return False

        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
             print(f"\nError checking/waiting for KB Scan completion: {e}")
             logger.error(f"Error checking/waiting for KB scan '{scan_code}' during gate evaluation: {e}", exc_info=True)
             # If we can't confirm scan completion, fail the gates
             return False
        except Exception as e:
             print(f"\nUnexpected error checking KB Scan status: {e}")
             logger.error(f"Unexpected error checking KB scan '{scan_code}' status: {e}", exc_info=True)
             return False

        # --- 2. Check for Pending Identifications ---
        print("\nChecking for Files Pending Identification...")
        try:
            pending_files_details = workbench.get_pending_files(scan_code)
            if pending_files_details:
                found_pending = True
                num_pending = len(pending_files_details)
                print(f"Check Result: Found {num_pending} file(s) Pending Identification.")
                if params.show_pending_files:
                    print("Files with Pending IDs:")
                    count = 0
                    for file_id, file_path in pending_files_details.items():
                        print(f"  - {file_path} (ID: {file_id})")
                        count += 1
                        if count >= 10:
                            print(f"  ... and {num_pending - count} more.")
                            break
            else:
                print("Check Result: No files found with Pending Identification.")
        except (ApiError, NetworkError) as e:
            print(f"\nWarning: Could not check for pending identifications due to API/Network error: {e}")
            logger.warning(f"API/Network error checking pending files for scan '{scan_code}': {e}")
            api_check_error = True # Mark that a check failed
        except Exception as e:
            print(f"\nWarning: Unexpected error checking for pending identifications: {e}")
            logger.warning(f"Unexpected error checking pending files for scan '{scan_code}': {e}", exc_info=True)
            api_check_error = True # Mark that a check failed

        # --- 3. Check Policy Violations ---
        print("\nChecking for Policy Violations...")
        try:
            policy_violations_details = workbench.get_policy_violations(scan_code) # Returns list of dicts or []
            total_violations = 0
            if policy_violations_details:
                for violation in policy_violations_details:
                    total_violations += violation.get('count', 0)

            if total_violations > 0:
                found_policy_violations = True
                print(f"Check Result: Found {total_violations} policy violation(s).")
                if params.show_policy_summary:
                    print("Policy Violation Summary:")
                    for violation in policy_violations_details:
                         print(f"  - Level: {violation.get('level', 'N/A')}, Count: {violation.get('count', 0)}")
            else:
                print("Check Result: No policy violations found.")

        except (ApiError, NetworkError) as e:
            print(f"\nWarning: Could not check for policy violations due to API/Network error: {e}")
            logger.warning(f"API/Network error checking policy violations for scan '{scan_code}': {e}")
            api_check_error = True # Mark that a check failed
        except Exception as e:
            print(f"\nWarning: Unexpected error checking for policy violations: {e}")
            logger.warning(f"Unexpected error checking policy violations for scan '{scan_code}': {e}", exc_info=True)
            api_check_error = True # Mark that a check failed

        # --- 4. Determine Final Gate Status based on --fail-on ---
        final_gates_passed = True
        failure_reason = []

        if api_check_error:
             # If we couldn't perform the checks reliably, fail the gate unless --fail-on is 'none'
             if params.fail_on != 'none':
                 final_gates_passed = False
                 failure_reason.append("API error during checks")
             else:
                 print("\nWarning: API errors occurred during checks, but --fail-on=none specified. Passing gates.")

        else:
            # Apply failure conditions based on checks performed
            if params.fail_on in ['pending', 'both'] and found_pending:
                final_gates_passed = False
                failure_reason.append("pending identifications found")

            if params.fail_on in ['policy', 'both'] and found_policy_violations:
                final_gates_passed = False
                failure_reason.append("policy violations found")

        # --- 5. Print Final Status ---
        print("\n--- Final Gate Status ---")
        if final_gates_passed:
            print("Result: PASSED")
        else:
            print(f"Result: FAILED (Reason(s): {', '.join(failure_reason)})")
        print("-------------------------")

        return final_gates_passed

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError,
            ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        # If resolution or fundamental API calls fail, re-raise to indicate command failure
        raise
    except Exception as e:
        # Wrap unknown exceptions
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})