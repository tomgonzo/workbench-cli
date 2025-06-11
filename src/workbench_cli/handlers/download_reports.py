# workbench_cli/handlers/download_reports.py

import os
import logging
import argparse
from typing import Set

from ..api import WorkbenchAPI
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _save_report_content,
    _wait_for_scan_completion,
    handler_error_wrapper
)
from ..exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    FileSystemError,
    ValidationError,
    ProcessError,
    ProcessTimeoutError
)

# Get logger from the handlers package
from . import logger

@handler_error_wrapper
def handle_download_reports(workbench: WorkbenchAPI, params: argparse.Namespace):
    """
    Handler for the 'download-reports' command. 
    Downloads reports for a scan or project.
    
    Args:
        workbench: The Workbench API client
        params: Command line parameters
        
    Returns:
        True if the operation was successful
        
    Raises:
        Various exceptions based on errors that occur during the process
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Process report_types (comma-separated list or ALL)
    report_types = set()
    if not params.report_type or params.report_type.upper() == "ALL":
        if params.report_scope == "scan":
            report_types = workbench.SCAN_REPORT_TYPES
        else:  # project
            report_types = workbench.PROJECT_REPORT_TYPES
    else:
        # Split comma-separated list
        for rt in params.report_type.split(","):
            rt = rt.strip().lower()
            # Validate report type
            if params.report_scope == "scan" and rt not in workbench.SCAN_REPORT_TYPES:
                raise ValidationError(f"Report type '{rt}' is not supported for scan scope reports. "
                                   f"Supported types: {', '.join(sorted(list(workbench.SCAN_REPORT_TYPES)))}")
            elif params.report_scope == "project" and rt not in workbench.PROJECT_REPORT_TYPES:
                raise ValidationError(f"Report type '{rt}' is not supported for project scope reports. "
                                   f"Supported types: {', '.join(sorted(list(workbench.PROJECT_REPORT_TYPES)))}")
            report_types.add(rt)
    
    logger.debug(f"Resolved report types to download: {report_types}")
    
    # Create output directory if it doesn't exist
    output_dir = params.report_save_path
    if not os.path.exists(output_dir):
        print(f"Creating output directory: {output_dir}")
        os.makedirs(output_dir, exist_ok=True)
    
    # Resolve project, scan
    print(f"\nResolving {'scan' if params.report_scope == 'scan' else 'project'} '{params.scan_name if params.report_scope == 'scan' else params.project_name}'...")
    
    project_code = None
    scan_code = None
    
    if params.project_name:
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
    
    if params.report_scope == "scan":
        # If scan scope, we need a scan code
        if params.scan_name:
            # Try to resolve using project context first if provided
            if project_code and params.project_name:
                scan_code, _ = _resolve_scan(
                    workbench,
                    scan_name=params.scan_name,
                    project_name=params.project_name,
                    create_if_missing=False,
                    params=params
                )
            else:
                # Try to resolve globally if project not provided
                scan_code, _ = _resolve_scan(
                    workbench,
                    scan_name=params.scan_name,
                    project_name=None,
                    create_if_missing=False,
                    params=params
                )
        else:
            raise ValidationError("Scan name is required for scan scope reports")
    elif not project_code:
        # If project scope but no project_code, that's an error
        raise ValidationError("Project name is required for project scope reports")
    
    # Check scan completion status for scan-scope reports
    if params.report_scope == "scan" and scan_code:
        print("\nChecking scan completion status...")
        try:
            # Wait for scan to complete before generating reports
            kb_scan_completed, da_completed, _ = _wait_for_scan_completion(workbench, params, scan_code)
            
            if not kb_scan_completed:
                print("\nWarning: The KB scan has not completed successfully. Reports may be incomplete.")
                logger.warning(f"Generating reports for scan '{scan_code}' that has not completed successfully.")
            
            # Dependency analysis might be relevant for certain report types
            if not da_completed:
                print("\nNote: Dependency Analysis has not completed. Some reports may have incomplete information.")
                logger.warning(f"Generating reports for scan '{scan_code}' without completed DA.")
        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            print(f"\nWarning: Could not verify scan completion status: {e}")
            print("Proceeding to generate reports anyway, but they may be incomplete.")
            logger.warning(f"Could not verify scan completion for '{scan_code}': {e}. Proceeding anyway.")
    
    # Generate and download reports based on scope
    print(f"\nGenerating and downloading {len(report_types)} {'project' if params.report_scope == 'project' else 'scan'} report(s)...")
    
    # Print the actual report types being downloaded
    for rt in sorted(report_types):
        print(f"- {rt}")
    
    # Track results for summary
    success_count = 0
    error_count = 0
    error_types = []
    
    # Process each report type sequentially
    for report_type in sorted(report_types):
        print(f"\nProcessing {report_type} report...")
        
        try:
            # Generate the report
            print(f"Generating {report_type} report...")
            
            # Get the right name component for file naming
            name_component = params.project_name if params.report_scope == "project" else params.scan_name
            
            # Common parameters for report generation
            common_params = {
                "scope": params.report_scope,
                "project_code": project_code,
                "scan_code": scan_code,
                "report_type": report_type,
            }
            
            # Add optional parameters if they were provided
            if params.selection_type is not None:
                common_params["selection_type"] = params.selection_type
            
            if params.selection_view is not None:
                common_params["selection_view"] = params.selection_view
            
            if params.disclaimer is not None:
                common_params["disclaimer"] = params.disclaimer
            
            # Include VEX data if requested (default is True)
            common_params["include_vex"] = params.include_vex
            
            # Check if this report type is synchronous or asynchronous
            is_async = (report_type in workbench.ASYNC_REPORT_TYPES)
            
            # Start report generation
            if is_async:
                # Asynchronous report generation
                print(f"Starting asynchronous generation of {report_type} report...")
                process_id = workbench.generate_report(**common_params)
                
                # Wait for report generation to complete using workbench._wait_for_process
                try:
                    print(f"Waiting for {report_type} report generation to complete...")
                    workbench._wait_for_process(
                        process_description=f"'{report_type}' report generation (Process ID: {process_id})",
                        check_function=workbench.check_report_generation_status,
                        check_args={
                            "scope": params.report_scope,
                            "process_id": process_id,
                            "scan_code": scan_code,
                            "project_code": project_code
                        },
                        status_accessor=lambda data: data.get("progress_state", "UNKNOWN"),
                        success_values={"FINISHED"},
                        failure_values={"FAILED", "CANCELLED", "ERROR"},
                        max_tries=getattr(params, 'scan_number_of_tries', 60),
                        # Use a fixed 3-second interval for report generation consistency with other waiters
                        wait_interval=3,
                        progress_indicator=True
                    )
                    print(f"Report generation complete!")
                except (ProcessTimeoutError, ProcessError) as e:
                    logger.error(f"Failed waiting for '{report_type}' report (Process ID: {process_id}): {e}")
                    error_count += 1
                    error_types.append(report_type)
                    continue
                except (ApiError, NetworkError) as e:
                    logger.error(f"API error during '{report_type}' report generation (Process ID: {process_id}): {e}")
                    error_count += 1
                    error_types.append(report_type)
                    continue
                except Exception as e:
                    logger.error(f"Unexpected error during '{report_type}' report generation (Process ID: {process_id}): {e}", exc_info=True)
                    error_count += 1
                    error_types.append(report_type)
                    continue
                
                # Download the generated report
                print(f"Downloading {report_type} report...")
                response = workbench.download_report(scope=params.report_scope, process_id=process_id)
            
            else:
                # Synchronous report generation (returns response directly)
                print(f"Directly downloading {report_type} report...")
                response = workbench.generate_report(**common_params)
            
            # Save the report content
            _save_report_content(response, output_dir, params.report_scope, name_component, report_type)
            print(f"Successfully saved {report_type} report.")
            success_count += 1
            
        except (ApiError, NetworkError, FileSystemError, ValidationError) as e:
            print(f"Error processing {report_type} report: {getattr(e, 'message', str(e))}")
            logger.error(f"Failed to generate/download {report_type} report: {e}", exc_info=True)
            error_count += 1
            error_types.append(report_type)
    
    # Print summary
    print("\n" + "="*50)
    print(f"Report Download Summary")
    print("="*50)
    print(f"Total reports requested: {len(report_types)}")
    print(f"Successfully downloaded: {success_count}")
    if error_count > 0:
        print(f"Failed to download: {error_count} ({', '.join(error_types)})")
    print("="*50)
    
    # Return True if at least one report was successfully downloaded
    return success_count > 0
