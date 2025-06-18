import os
import time
import logging
import argparse
from typing import Dict, Any, TYPE_CHECKING

from ..utilities.error_handling import handler_error_wrapper
from ..utilities.scan_workflows import (
    fetch_display_save_results,
    print_operation_summary,
    determine_scans_to_run
)
from ..utilities.scan_target_validators import ensure_scan_compatibility, validate_reuse_source
from ..utilities import (
    get_git_repo_root,
    get_changed_files,
    create_diff_archive,
    autodetect_git_refs
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

if TYPE_CHECKING:
    from ..api import WorkbenchAPI

logger = logging.getLogger("workbench-cli")


@handler_error_wrapper
def handle_scan_git_diff(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan-git-diff' command. Creates an archive of changed files
    between two git refs and scans it.
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # This command must not have a path argument
    if hasattr(params, 'path') and params.path:
        raise ValidationError("The 'scan-git-diff' command does not accept a 'path' argument.")

    # Auto-detect refs if not provided by the user
    base_ref = params.base_ref
    compare_ref = params.compare_ref

    # Only attempt auto-detection if the base ref was not explicitly provided
    if not base_ref:
        detected_base, detected_head = autodetect_git_refs()
        if detected_base and detected_head:
            base_ref = detected_base
            # If compare_ref still has its default value, override it with the detected one
            if compare_ref == 'HEAD':
                compare_ref = detected_head

    # After attempting auto-detection, validate that we have a base_ref
    if not base_ref:
        raise ValidationError(
            "A '--base-ref' must be provided or be discoverable in a supported CI/CD environment (e.g., a GitHub PR)."
        )

    temp_zip_path = None
    try:
        # 1. Determine files to scan from git diff
        print(f"\nFinding changed files between '{base_ref}' and '{compare_ref}'...")
        repo_root = get_git_repo_root()
        changed_files = get_changed_files(base_ref, compare_ref)

        if not changed_files:
            print("\n✅ No new or modified files to scan. Operation complete.")
            return True

        print(f"Found {len(changed_files)} changed file(s) to scan.")
        
        # 2. Create a temporary archive of the changed files
        print("Creating a temporary archive of changed files...")
        temp_zip_path = create_diff_archive(changed_files, repo_root)
        print(f"Temporary archive created at: {temp_zip_path}")
        
        # This is where the logic from handle_scan starts, but using the temp_zip_path
        
        # Initialize timing dictionary
        durations = {
            "kb_scan": 0.0,
            "dependency_analysis": 0.0,
            "extraction_duration": 0.0
        }
        
        # Validate ID reuse source early
        api_reuse_type = None
        resolved_specific_code_for_reuse = None
        if getattr(params, 'id_reuse', False):
            print("\nValidating ID reuse source before proceeding...")
            try:
                api_reuse_type, resolved_specific_code_for_reuse = validate_reuse_source(workbench, params)
                print(f"Successfully validated ID reuse source.")
            except Exception as e:
                logger.warning(f"ID reuse validation failed ({type(e).__name__}): {e}. Continuing without ID reuse.")
                params.id_reuse = False

        # Resolve project and scan (find or create)
        print("\nChecking if the Project and Scan exist or need to be created...")
        project_code = workbench.resolve_project(params.project_name, create_if_missing=True)
        scan_code, scan_id = workbench.resolve_scan(
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        ensure_scan_compatibility(workbench, params, scan_code)

        print("\nEnsuring the Scan is idle before uploading code...")
        workbench.assert_process_can_start("SCAN", scan_code, wait_max_tries=60, wait_interval=30)
        workbench.assert_process_can_start("DEPENDENCY_ANALYSIS", scan_code, wait_max_tries=60, wait_interval=30)

        print("\nClearing existing scan content...")
        try:
            workbench.remove_uploaded_content(scan_code, "")
            print("Successfully cleared existing scan content.")
        except Exception as e:
            logger.warning(f"Failed to clear existing scan content: {e}")
            print(f"Warning: Could not clear existing scan content: {e}")

        print("\nUploading Code to Workbench...")
        workbench.upload_scan_target(scan_code, temp_zip_path)
        print(f"Successfully uploaded archive to Workbench.")

        # --- Early Cleanup of Temporary Archive ---
        # The archive is no longer needed locally after a successful upload.
        # The 'finally' block will handle cleanup if the upload fails.
        print(f"\nCleaning up temporary archive: {temp_zip_path}")
        os.remove(temp_zip_path)
        # Set path to None to prevent the finally block from trying to delete it again
        temp_zip_path = None

        print("\nExtracting Uploaded Archive...")
        extraction_triggered = workbench.extract_archives(
            scan_code, params.recursively_extract_archives, params.jar_file_extraction
        )
        
        if extraction_triggered:
            if workbench._is_status_check_supported(scan_code, "EXTRACT_ARCHIVES"):
                try:
                    _, extraction_duration = workbench.wait_for_archive_extraction(
                        scan_code, params.scan_number_of_tries, 5
                    )
                    durations["extraction_duration"] = extraction_duration
                except Exception as e:
                    logger.error(f"Archive extraction issue: {e}")
                    print(f"\nWARNING: Archive extraction encountered an issue: {e}")
            else:
                print("Archive extraction status check not supported. Waiting 3 seconds before continuing...")
                time.sleep(3)
        else:
            print("No archives to extract. Continuing with scan...")

        workbench.assert_process_can_start(
            "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
        )
        
        scan_operations = determine_scans_to_run(params)
        
        scan_completed = False
        da_completed = False
        
        if not scan_operations["run_kb_scan"] and scan_operations["run_dependency_analysis"]:
            print("\nStarting Dependency Analysis only (skipping KB scan)...")
            workbench.start_dependency_analysis(scan_code, import_only=False)
            
            if getattr(params, 'no_wait', False):
                print("Dependency Analysis has been started. Exiting without waiting for completion.")
                return True
            
            try:
                _, da_duration = workbench.wait_for_scan_to_finish(
                    "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time
                )
                durations["dependency_analysis"] = da_duration
                da_completed = True
                print_operation_summary(params, da_completed, project_code, scan_code, durations)
                if any([params.show_licenses, params.show_components, params.show_dependencies,
                        params.show_scan_metrics, params.show_policy_warnings, params.show_vulnerabilities]):
                    fetch_display_save_results(workbench, params, scan_code)
                return True
            except Exception as e:
                logger.error(f"Error waiting for dependency analysis to complete: {e}", exc_info=True)
                print(f"\nError: Dependency analysis failed: {e}")
                return False
        
        if scan_operations["run_kb_scan"]:
            print("\nStarting KB Scan Process...")
            workbench.run_scan(
                scan_code,
                params.limit,
                params.sensitivity,
                params.autoid_file_licenses,
                params.autoid_file_copyrights,
                params.autoid_pending_ids,
                params.delta_scan,
                params.id_reuse,
                api_reuse_type if params.id_reuse else None,
                resolved_specific_code_for_reuse if params.id_reuse else None,
                run_dependency_analysis=scan_operations["run_dependency_analysis"]
            )
            
            if getattr(params, 'no_wait', False):
                print("\nKB Scan started. Exiting without waiting for completion.")
                return True
            else:
                _, kb_duration = workbench.wait_for_scan_to_finish(
                    "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
                )
                durations["kb_scan"] = kb_duration
                scan_completed = True
                
                if scan_completed and scan_operations["run_dependency_analysis"]:
                    print("\nWaiting for Dependency Analysis to complete...")
                    try:
                        _, da_duration = workbench.wait_for_scan_to_finish(
                            "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time,
                        )
                        durations["dependency_analysis"] = da_duration
                        da_completed = True
                    except Exception as e:
                        logger.warning(f"Error waiting for dependency analysis to complete: {e}")
                        print(f"\nWarning: Error waiting for dependency analysis to complete: {e}")
                        da_completed = False
            
            print_operation_summary(params, da_completed, project_code, scan_code, durations)
            
            if any([params.show_licenses, params.show_components, params.show_dependencies,
                    params.show_scan_metrics, params.show_policy_warnings, params.show_vulnerabilities]):
                fetch_display_save_results(workbench, params, scan_code)
            
            return True
        return True # Fallback success
    finally:
        # Ensure cleanup of the temporary file if any step before cleanup failed
        if temp_zip_path and os.path.exists(temp_zip_path):
            print(f"\nCleaning up temporary archive: {temp_zip_path}")
            os.remove(temp_zip_path)
