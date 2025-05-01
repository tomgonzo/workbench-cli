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
    print(f"\n--- Running {params.command.upper()} Command ---")
    # Initialize check results
    found_pending = False
    found_policy_warnings = False
    found_vulnerabilities = False
    vulnerability_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    pending_files_details = {}
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

        # --- 1. Check Scan and DA Completion Status ---
        print("\nEnsuring the Scan finished...")
        try:
             kb_status_data = workbench.get_scan_status("SCAN", scan_code)
             kb_status = kb_status_data.get("status", "UNKNOWN").upper()
             logging.debug(f"Current Scan status: {kb_status}")
             if kb_status not in {"FINISHED", "FAILED", "CANCELLED"}:
                 print("KB Scan is not finished. Waiting...")
                 workbench.wait_for_scan_to_finish(
                     "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
                 )
                 print("KB Scan finished.")
                 # Re-check status after waiting
                 kb_status_data = workbench.get_scan_status("SCAN", scan_code)
                 kb_status = kb_status_data.get("status", "UNKNOWN").upper()

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
        
        print("\nEnsuring Dependency Analysis finished...")
        try:
             da_status_data = workbench.get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
             da_status = da_status_data.get("status", "UNKNOWN").upper()
             logging.debug(f"Current KB Scan status: {kb_status}")
             if kb_status not in {"FINISHED", "FAILED", "CANCELLED"}:
                 print("Dependency Analysis has not finished. Waiting...")
                 workbench.wait_for_scan_to_finish(
                     "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time
                 )
                 print("Dependency Analysis finished.")
                 # Re-check status after waiting
                 da_status_data = workbench.get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
                 da_status = da_status_data.get("status", "UNKNOWN").upper()

             if da_status in {"FAILED", "CANCELLED"}:
                  print(f"Error: Dependency Analysis {da_status}. Cannot evaluate gates.")
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
        print("\nChecking Pending Identifications...")
        try:
            pending_files_details = workbench.get_pending_files(scan_code)
            if pending_files_details:
                found_pending = True
                num_pending = len(pending_files_details)
                print(f"Check Result: Found {num_pending} file(s) Pending Identification.")
                if params.show_pending_files:
                    print("Files Pending Identification:")
                    count = 0
                    for file_id, file_path in pending_files_details.items():
                        print(f"  - {file_path} (ID: {file_id})")
                        count += 1
                        if count >= 10:
                            print(f"  ... and {num_pending - count} more.")
                            break
            else:
                print("Check Result: No Files are Pending Identification.")
        except (ApiError, NetworkError) as e:
            print(f"\nWarning: Could not check for pending identifications due to API/Network error: {e}")
            logger.warning(f"API/Network error checking pending files for scan '{scan_code}': {e}")
            api_check_error = True # Mark that a check failed
        except Exception as e:
            print(f"\nWarning: Unexpected error checking for pending identifications: {e}")
            logger.warning(f"Unexpected error checking pending files for scan '{scan_code}': {e}", exc_info=True)
            api_check_error = True # Mark that a check failed

        # --- 3. Check Policy Violations ---
        print("\nChecking Policy Violations...")
        try:
            policy_warnings_data = workbench.scans_get_policy_warnings_counter(scan_code)
    
            # Get totals from the data
            total_warnings = int(policy_warnings_data.get("policy_warnings_total", 0))
            files_with_warnings = int(policy_warnings_data.get("identified_files_with_warnings", 0))
            deps_with_warnings = int(policy_warnings_data.get("dependencies_with_warnings", 0))
            
            if total_warnings > 0:
                found_policy_warnings = True
                print(f"There are {total_warnings} policy warnings. "
                      f"Warnings in Identified Files: {files_with_warnings}. "
                      f"Warnings in Dependencies: {deps_with_warnings}.")
                
            else:
                print("Check Result: No Files, Components, or Dependencies with policy warnings.")

        except (ApiError, NetworkError) as e:
            print(f"\nWarning: Could not check for policy violations due to API/Network error: {e}")
            logger.warning(f"API/Network error checking policy violations for scan '{scan_code}': {e}")
            api_check_error = True # Mark that a check failed
        except Exception as e:
            print(f"\nWarning: Unexpected error checking for policy violations: {e}")
            logger.warning(f"Unexpected error checking policy violations for scan '{scan_code}': {e}", exc_info=True)
            api_check_error = True # Mark that a check failed

        # --- 4. Check for Vulnerabilities ---
        print("\nChecking Vulnerabilities...")
        try:
            vulnerabilities_data = workbench.list_vulnerabilities(scan_code)
            if vulnerabilities_data:
                found_vulnerabilities = True
                num_cves = len(vulnerabilities_data)
                unique_components = set()

                for vuln in vulnerabilities_data:
                    severity = vuln.get("severity", "UNKNOWN").upper()
                    # Ensure we only count known severities in our predefined dict
                    if severity in vulnerability_counts:
                        vulnerability_counts[severity] += 1
                    else: # Count anything else as UNKNOWN
                        vulnerability_counts["UNKNOWN"] += 1

                    # Collect unique components for the summary message
                    comp_name = vuln.get("component_name", "Unknown")
                    comp_version = vuln.get("component_version", "Unknown")
                    unique_components.add(f"{comp_name}:{comp_version}")

                num_unique_components = len(unique_components)
                print(f"Check Result: Found {num_cves} vulnerabilities affecting {num_unique_components} components.")
                print(f"  By CVSS Score, "
                      f"{vulnerability_counts['CRITICAL']} are Critical, "
                      f"{vulnerability_counts['HIGH']} are High, "
                      f"{vulnerability_counts['MEDIUM']} are Medium, and "
                      f"{vulnerability_counts['LOW']} are Low.")

                if vulnerability_counts['UNKNOWN'] > 0:
                    print(f"  - Unknown:  {vulnerability_counts['UNKNOWN']}")
            else:
                print("Check Result: No vulnerabilities found.")

        except ScanNotFoundError:
             # If scan exists but vuln check fails specifically with ScanNotFound, treat as no vulns found for gate purposes
             print("Check Result: Vulnerability data not available (ScanNotFound during vuln check). Assuming no vulnerabilities for gate check.")
             logger.warning(f"Scan '{scan_code}' found, but vulnerability check resulted in ScanNotFound. Treating as 0 vulnerabilities.")
        except (ApiError, NetworkError) as e:
            print(f"\nWarning: Could not check for vulnerabilities due to API/Network error: {e}")
            logger.warning(f"API/Network error checking vulnerabilities for scan '{scan_code}': {e}")
            api_check_error = True # Mark that a check failed
        except Exception as e:
            print(f"\nWarning: Unexpected error checking for vulnerabilities: {e}")
            logger.warning(f"Unexpected error checking vulnerabilities for scan '{scan_code}': {e}", exc_info=True)
            api_check_error = True # Mark that a check failed

        # --- 5. Determine Final Gate Status based on failure flags ---
        final_gates_passed = True
        failure_reason = []

        # Initialize Gates
        pending_status = "NOT USED"
        policy_status = "NOT USED"
        vuln_status = "NOT USED"

        if api_check_error:
             # If we couldn't perform the checks reliably, fail the gate if *any* failure condition is active
             if params.fail_on_pending or params.fail_on_policy or params.fail_on_vuln_severity:
                 final_gates_passed = False
                 failure_reason.append("API error during checks")
             else:
                 print("\nWarning: API errors occurred during checks, but no --fail-on-* flags specified. Passing gates.")

        else:
            # Apply failure conditions based on checks performed
            if params.fail_on_pending and found_pending:
                if found_pending:
                    pending_status = "FAIL"
                    final_gates_passed = False
                    failure_reason.append("pending identifications found")
                else:
                    pending_status = "PASS"

            if params.fail_on_policy and found_policy_warnings:
                if found_policy_warnings:
                    policy_status = "FAIL"
                    final_gates_passed = False
                    failure_reason.append("policy violations found")
                else:
                    policy_status = "PASS"

            # Check vulnerability severity gate
            if params.fail_on_vuln_severity and found_vulnerabilities:
                fail_severity_level = params.fail_on_vuln_severity.upper()
                severities_to_check = []
                if fail_severity_level == 'LOW':
                    severities_to_check = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
                elif fail_severity_level == 'MEDIUM':
                    severities_to_check = ['CRITICAL', 'HIGH', 'MEDIUM']
                elif fail_severity_level == 'HIGH':
                    severities_to_check = ['CRITICAL', 'HIGH']
                elif fail_severity_level == 'CRITICAL':
                    severities_to_check = ['CRITICAL']

                vulnerability_failed = False
                for severity in severities_to_check:
                    if vulnerability_counts.get(severity, 0) > 0:
                        vulnerability_failed = True
                        final_gates_passed = False
                        failure_reason.append(f"vulnerabilities found at severity '{fail_severity_level}' or higher")
                        break # No need to check lower severities if already failed

                vuln_status = "FAIL" if vulnerability_failed else "PASS"
            elif params.fail_on_vuln_severity: # Flag was set, but no vulnerabilities were found
                vuln_status = "PASS"
            # else: vuln_status remains "NOT USED"

        # --- 6. Print Final Status ---
        print("\n--- Gate Evaluation Summary ---")
        print(f"Pending Identifications: {pending_status:<10}")
        print(f"Policy Violations:       {policy_status:<10}")
        print(f"Vulnerabilities:         {vuln_status:<10}")
        print("-----------------------------") # Adjusted length
        if final_gates_passed:
            print("Final Result: PASSED")
        else:
            print(f"Final Result: FAILED (Reason(s): {', '.join(failure_reason)})")
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