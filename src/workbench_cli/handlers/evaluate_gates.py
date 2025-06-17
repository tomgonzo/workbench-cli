# workbench_cli/handlers/evaluate_gates.py

import logging
import argparse
from typing import TYPE_CHECKING

from ..api import WorkbenchAPI
from ..utilities.error_handling import handler_error_wrapper
from ..exceptions import (
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ValidationError
)
from ..utilities.scan_workflows import wait_for_scan_completion

# Get logger from the handlers package
from . import logger

if TYPE_CHECKING:
    from ..api import WorkbenchAPI

@handler_error_wrapper
def handle_evaluate_gates(workbench: "WorkbenchAPI", params: "argparse.Namespace") -> bool:
    """
    Handler for the 'evaluate-gates' command. 
    Checks scan status and evaluates policy warnings.
    
    Args:
        workbench: The Workbench API client
        params: Command line parameters
        
    Returns:
        bool: True if all gates passed, False if any gate failed
        
    Raises:
        Various exceptions based on errors that occur during the process
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Resolve project and scan (find only)
    print("\nResolving scan for gate evaluation...")
    project_code = workbench.resolve_project(params.project_name, create_if_missing=False)
    scan_code, scan_id = workbench.resolve_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=False,
        params=params
    )
    
    # Wait for scan and dependency analysis to complete
    print("\nVerifying scan completion...")
    scan_completed, da_completed, _ = wait_for_scan_completion(workbench, params, scan_code)
    
    if not scan_completed:
        print("\n❌ Gate Evaluation Failed: KB Scan has not completed successfully.")
        return False
    
    # Track gate pass/fail states
    pending_files_gate_passed = True
    policy_gate_passed = True
    vuln_gate_passed = True
    
    # Check for pending files - always check this
    print("\nChecking for pending files...")
    pending_count = 0
    try:
        pending_files = workbench.get_pending_files(scan_code)
        pending_count = len(pending_files)
    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for pending files: {e}")
        logger.warning(f"Error checking pending files for scan '{scan_code}': {e}")
        # Only fail if pending files check is explicitly required
        if params.fail_on_pending:
            pending_files_gate_passed = False
            print(f"\n❌ Gate Failed: Unable to verify pending files status due to API error")
        pending_files = {}
    
    if pending_count > 0:
        if params.fail_on_pending:
            print(f"\n❌ Gate Failed: Found {pending_count} pending files that require identification.")
            pending_files_gate_passed = False
        else:
            print(f"\n⚠️ Warning: Found {pending_count} pending files that require identification.")
            print("Note: Gate is not set to fail on pending files (--fail-on-pending not specified).")
        
        # Display pending files if requested
        show_pending_files = getattr(params, 'show_pending_files', False)
        if show_pending_files and pending_count > 0:
            print("\nPending Files:")
            # Limit display to first 25 files
            file_items = list(pending_files.items())
            for i, (file_id, file_path) in enumerate(file_items):
                if i >= 25:
                    break
                print(f"  {file_path}")
            
            # Show a message if there are more files than displayed
            if pending_count > 25:
                print(f"  ... and {pending_count - 25} more files (showing first 25 of {pending_count} total)")
    else:
        print("\n✅ No pending files found - all files have been identified.")
    
    # Check for policy warnings - always check this
    print("\nChecking for policy warnings...")
    policy_data = None
    try:
        policy_data = workbench.get_policy_warnings_counter(scan_code)
        
        # Extract the count correctly based on the API response structure
        # The API might return {data: {policy_warnings_total: N}} or just {policy_warnings_total: N}
        if isinstance(policy_data, dict):
            if "data" in policy_data and isinstance(policy_data["data"], dict):
                policy_warning_count = policy_data["data"].get("policy_warnings_total", 0)
            else:
                policy_warning_count = policy_data.get("policy_warnings_total", 
                                     policy_data.get("total", 0))  # Fallback to 'total' for backward compatibility
        else:
            policy_warning_count = 0
            logger.warning(f"Unexpected policy warnings data format: {policy_data}")
        
        if policy_warning_count > 0:
            if params.fail_on_policy:
                print(f"\n❌ Gate Failed: Found {policy_warning_count} policy warnings.")
                policy_gate_passed = False
            else:
                print(f"\n⚠️ Warning: Found {policy_warning_count} policy warnings.")
                print("Note: Gate is not set to fail on policy (--fail-on-policy not specified).")
        else:
            print("\n✅ No policy warnings found.")
    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for policy warnings: {e}")
        logger.warning(f"Error checking policy warnings for scan '{scan_code}': {e}")
        if params.fail_on_policy:
            policy_gate_passed = False
            print(f"\n❌ Gate Failed: Unable to verify policy warnings status due to API error")
    
    # Check for vulnerabilities - always check this
    print("\nChecking for vulnerabilities...")
    try:
        vulnerabilities = workbench.list_vulnerabilities(scan_code)
        
        # Count vulnerabilities by severity
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
        severities_order = ["critical", "high", "medium", "low"]
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in vuln_counts:
                vuln_counts[severity] += 1
            else:
                vuln_counts["other"] += 1
        
        total_vulns = sum(vuln_counts.values())
        
        if total_vulns > 0:
            
            # Check if we should fail based on severity threshold
            if params.fail_on_vuln_severity:
                threshold_idx = severities_order.index(params.fail_on_vuln_severity)
                has_threshold_vulns = False
                
                for severity in severities_order[:threshold_idx + 1]:
                    if vuln_counts[severity] > 0:
                        has_threshold_vulns = True
                        print(f"\n❌ Gate Failed: Found vulnerabilities with severity {severity.upper()} (threshold: {params.fail_on_vuln_severity.upper()})")
                        vuln_gate_passed = False
                        break
                
                if vuln_gate_passed:
                    print(f"\n✅ No vulnerabilities found with severity {params.fail_on_vuln_severity.upper()} or higher.")
            else:
                # If vulnerabilities exist but gate is not set to fail
                print(f"\n⚠️ Warning: Found {total_vulns} vulnerabilities. By CVSS Score:")
                for severity in severities_order:
                    if vuln_counts[severity] > 0:
                        print(f" - {severity.upper()}: {vuln_counts[severity]}")
                print("Note: Gate is not set to fail on vulnerabilities (--fail-on-vuln-severity not specified).")
        else:
            print("\n✅ No vulnerabilities found.")
    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for vulnerabilities: {e}")
        logger.warning(f"Error checking vulnerabilities for scan '{scan_code}': {e}")
        if params.fail_on_vuln_severity:
            vuln_gate_passed = False
            print(f"\n❌ Gate Failed: Unable to verify vulnerabilities status due to API error")
    
    # Final gate evaluation summary
    print("\n" + "="*50)
    print("Gate Evaluation Summary:")
    print("="*50)
    
    all_gates_passed = pending_files_gate_passed and policy_gate_passed and vuln_gate_passed
    
    if params.fail_on_pending:
        status = "✅ PASSED" if pending_files_gate_passed else "❌ FAILED"
        print(f"Pending Files Gate: {status} ({pending_count} pending files)")
    else:
        print(f"Pending Files: {pending_count} files {'✅' if pending_count == 0 else '⚠️'}")
    
    if params.fail_on_policy:
        if policy_data and isinstance(policy_data, dict):
            if 'data' in policy_data and isinstance(policy_data['data'], dict):
                policy_count = policy_data['data'].get('policy_warnings_total', 0)
            else:
                policy_count = policy_data.get('policy_warnings_total', policy_data.get('total', 0))
        else:
            policy_count = "Not Checked"
        status = "✅ PASSED" if policy_gate_passed else "❌ FAILED"
        print(f"Policy Warnings Gate: {status} ({policy_count} warnings)")
    else:
        policy_count = "Not Checked"
        if policy_data and isinstance(policy_data, dict):
            if 'data' in policy_data and isinstance(policy_data['data'], dict):
                policy_count = policy_data['data'].get('policy_warnings_total', 0)
            else:
                policy_count = policy_data.get('policy_warnings_total', policy_data.get('total', 0))
        print(f"Policy Warnings: {policy_count} warnings {'✅' if policy_count == 0 or policy_count == 'Not Checked' else '⚠️'}")
    
    if params.fail_on_vuln_severity:
        status = "✅ PASSED" if vuln_gate_passed else "❌ FAILED"
        print(f"Vulnerability Gate: {status} (Threshold: {params.fail_on_vuln_severity.upper()})")
    else:
        total_vulns = sum(vuln_counts.values()) if 'vuln_counts' in locals() else "Not Checked"
        print(f"Vulnerabilities: {total_vulns} {'✅' if total_vulns == 0 or total_vulns == 'Not Checked' else '⚠️'}")
    
    print("="*50)
    print(f"Overall Gate Status: {'✅ PASSED' if all_gates_passed else '❌ FAILED'}")
    print("="*50)
    
    return all_gates_passed
