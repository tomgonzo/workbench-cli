# workbench_agent/handlers/download_reports.py

import os
import logging
import argparse
import requests

from ..api import Workbench
from ..utils import (
    _resolve_project,
    _resolve_scan,
    _save_report_content
)
from ..exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    FileSystemError,
    ValidationError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProcessError,
    ProcessTimeoutError
)

# Get logger
logger = logging.getLogger("log")


def handle_download_reports(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'download-reports' command. Generates and downloads reports.
    """
    print(f"\n--- Running Command: {params.command} ---")

    report_scope = params.report_scope.lower()
    project_code = None
    scan_code = None
    scan_id = None
    entity_name_log = ""
    name_for_file = ""

    try:
        if report_scope == "project":
            if not params.project_name:
                raise ValidationError("--project-name is required when --report-scope is 'project'.")
            project_name = params.project_name
            print(f"Resolving project '{project_name}' for report generation...")
            project_code = _resolve_project(workbench, project_name, create_if_missing=False)
            entity_name_log = f"Project '{project_code}'"
            name_for_file = project_name

        elif report_scope == "scan":
            if not params.scan_name:
                 raise ValidationError("--scan-name is required when --report-scope is 'scan'.")
            scan_name = params.scan_name
            if params.project_name:
                print(f"Resolving scan '{scan_name}' within project '{params.project_name}'...")
                project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
                scan_code, scan_id = _resolve_scan(
                    workbench, scan_name, params.project_name, create_if_missing=False, params=params
                )
                entity_name_log = f"Scan '{scan_code}' (ID: {scan_id}) in Project '{project_code}'"
            else:
                print(f"Resolving scan '{scan_name}' globally...")
                scan_code, scan_id = _resolve_scan(
                    workbench, scan_name, project_name=None, create_if_missing=False, params=params
                )
                try:
                    all_scans = workbench.list_scans()
                    scan_info = next((s for s in all_scans if s.get('code') == scan_code), None)
                    if scan_info and scan_info.get('project_code'):
                        project_code = scan_info['project_code']
                        logger.debug(f"Resolved project_code '{project_code}' for globally found scan '{scan_code}'.")
                        entity_name_log = f"Scan '{scan_code}' (ID: {scan_id}) in Project '{project_code}'"
                    else:
                        raise ProjectNotFoundError(f"Could not determine project context for globally found scan '{scan_code}'. Scan Info: {scan_info}")
                except Exception as proj_lookup_err:
                     raise ProjectNotFoundError(f"Failed to find project context for globally resolved scan '{scan_code}': {proj_lookup_err}")

            name_for_file = scan_name

        else:
            raise ValidationError(f"Invalid report scope: {report_scope}. Must be 'scan' or 'project'.")

    except (ProjectNotFoundError, ScanNotFoundError, ValidationError) as e:
        raise
    except Exception as e:
        logger.error(f"Error resolving project/scan for report download: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Error resolving project/scan: {str(e)}",
                                details={"error": str(e)})

    print(f"\n--- Generating and Downloading Reports for {entity_name_log} ---")

    report_types_to_download = []
    requested_type_input = params.report_type

    allowed_types = Workbench.PROJECT_REPORT_TYPES if report_scope == "project" else Workbench.SCAN_REPORT_TYPES
    allowed_types_list = sorted(list(allowed_types))

    if requested_type_input.upper() == "ALL":
        report_types_to_download = allowed_types_list
        print(f"Report Scope is '{report_scope}'. All available reports will be downloaded: {', '.join(report_types_to_download)}")
    else:
        requested_types_list = [t.strip().lower() for t in requested_type_input.split(',') if t.strip()]
        if not requested_types_list:
             raise ValidationError("No valid report types provided in --report-type (or input was empty after splitting).")

        print(f"Requested report types: {', '.join(requested_types_list)}")
        invalid_types = [req_type for req_type in requested_types_list if req_type not in allowed_types]

        if invalid_types:
            raise ValidationError(
                f"Invalid report type(s) for '{report_scope}' scope: {', '.join(invalid_types)}. "
                f"Allowed types are: {', '.join(allowed_types_list)}"
            )

        report_types_to_download = sorted(list(set(requested_types_list)))
        print(f"Processing validated report types: {', '.join(report_types_to_download)}")

    output_directory = params.report_save_path
    try:
        os.makedirs(output_directory, exist_ok=True)
        print(f"Reports will be saved to directory: {os.path.abspath(output_directory)}")
    except OSError as e:
        raise FileSystemError(f"Could not create output directory '{output_directory}': {e}") from e

    successful_reports = []
    failed_reports = []

    for report_type in report_types_to_download:
        print(f"\nProcessing '{report_type}' report...")
        process_id = None
        try:
            print(f"Requesting generation of '{report_type}' report...")
            generation_result = workbench.generate_report(
                scope=report_scope,
                project_code=project_code,
                scan_code=scan_code,
                report_type=report_type,
                selection_type=params.selection_type,
                selection_view=params.selection_view,
                disclaimer=params.disclaimer,
                include_vex=params.include_vex
            )
            logger.debug(f"generate_report result type: {type(generation_result)}, value: {generation_result}")

            if isinstance(generation_result, requests.Response):
                print(f"Synchronous report '{report_type}' generated directly.")
                _save_report_content(
                    generation_result,
                    output_directory,
                    report_scope=report_scope,
                    name_component=name_for_file,
                    report_type=report_type
                )
                successful_reports.append(report_type)
                continue

            elif isinstance(generation_result, int) and generation_result > 0:
                process_id = generation_result
                print(f"Asynchronous report generation started (Process ID: {process_id}). Waiting for completion...")

                try:
                    workbench._wait_for_process(
                        process_description=f"'{report_type}' report generation (Process ID: {process_id})",
                        check_function=workbench.check_report_generation_status,
                        check_args={
                            "scope": report_scope,
                            "process_id": process_id,
                            "scan_code": scan_code,
                            "project_code": project_code
                        },
                        status_accessor=lambda data: data.get("progress_state", "UNKNOWN"),
                        success_values={"FINISHED"},
                        failure_values={"FAILED", "CANCELLED"},
                        max_tries=params.scan_number_of_tries,
                        wait_interval=5,
                        progress_indicator=True
                    )
                    print(f"Report generation complete (Process ID: {process_id}).")
                except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
                    raise ProcessError(f"Failed waiting for '{report_type}' report (Process ID: {process_id}): {e}", details=getattr(e, 'details', None)) from e
                except Exception as e:
                    logger.error(f"Unexpected error waiting for report '{report_type}' (Process ID: {process_id}): {e}", exc_info=True)
                    raise WorkbenchAgentError(f"Unexpected error waiting for report '{report_type}': {e}",
                                            details={"error": str(e), "process_id": process_id}) from e

                print(f"Downloading report '{report_type}' (Process ID: {process_id})...")
                try:
                    download_response = workbench.download_report(report_scope, process_id)
                    _save_report_content(
                        download_response,
                        output_directory,
                        report_scope=report_scope,
                        name_component=name_for_file,
                        report_type=report_type
                    )
                    successful_reports.append(report_type)
                except (ApiError, NetworkError) as e:
                    raise ApiError(f"Failed to download report '{report_type}' (Process ID: {process_id}): {e}", details=getattr(e, 'details', None)) from e
                except Exception as e:
                    logger.error(f"Unexpected error downloading report '{report_type}' (Process ID: {process_id}): {e}", exc_info=True)
                    raise WorkbenchAgentError(f"Unexpected error downloading report '{report_type}': {e}",
                                            details={"error": str(e), "process_id": process_id}) from e

            else:
                raise ProcessError(f"Unexpected result received from generate_report for '{report_type}': {generation_result}",
                                 details={"result": generation_result})

        except (ApiError, NetworkError, ProcessError, ProcessTimeoutError, FileSystemError, ValidationError) as e:
            print(f"Error processing '{report_type}' report: {e}")
            logger.warning(f"Failed to generate/download '{report_type}' report for {entity_name_log}. Error: {e}", exc_info=False)
            failed_reports.append(report_type)
        except Exception as e:
            print(f"Unexpected error processing '{report_type}' report: {e}")
            logger.error(f"Unexpected error processing '{report_type}' report for {entity_name_log}.", exc_info=True)
            failed_reports.append(report_type)

    print("\n--- Report Download Summary ---")
    if successful_reports:
        print(f"Successfully processed {len(successful_reports)} report(s): {', '.join(successful_reports)}")
    else:
        print("No reports were successfully processed.")
    if failed_reports:
        print(f"Failed to process {len(failed_reports)} report(s): {', '.join(failed_reports)}")
    else:
        print("No reports failed to process.")
    print("-----------------------------")

    if failed_reports:
        raise ProcessError(f"Failed to process one or more reports: {', '.join(failed_reports)}",
                         details={"failed_reports": failed_reports, "successful_reports": successful_reports})