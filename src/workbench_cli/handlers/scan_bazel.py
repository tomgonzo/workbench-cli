# workbench_cli/handlers/scan_bazel.py

import os
import logging
import argparse
from typing import TYPE_CHECKING, Dict, Set
from ..utilities.error_handling import handler_error_wrapper
from ..exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ValidationError,
    ProcessError,
    ProcessTimeoutError,
    ConfigurationError,
    AuthenticationError,
    ScanExistsError,
)
from ..utilities.scan_workflows import (
    wait_for_scan_completion, 
    determine_scans_to_run,
    print_operation_summary,
    fetch_display_save_results
)
from ..utilities.scan_target_validators import ensure_scan_compatibility, validate_reuse_source
from ..utilities.bazel_utils import BazelUtils
from ..utilities.prep_upload_archive import UploadArchivePrep

if TYPE_CHECKING:
    from ..api import WorkbenchAPI

logger = logging.getLogger("workbench-cli")

def _get_project_and_scan_codes(workbench: "WorkbenchAPI", params: argparse.Namespace) -> tuple[str, str]:
    """
    Resolve project and scan codes for Bazel scan with Bazel-specific metadata.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        tuple[str, str]: Project code and scan code
    """
    # Generate Bazel-specific metadata for project
    project_metadata = BazelUtils.generate_project_metadata(params.workspace_path, params.target)
    
    # Generate scan metadata with Git context for baseline detection
    scan_metadata = BazelUtils.generate_scan_metadata(
        workspace_path=params.workspace_path,
        target=params.target,
        baseline_commit=getattr(params, 'baseline_commit', None)
    )
    
    print(f"Creating project with Bazel metadata: {project_metadata['product_name']}")
    project_code = workbench.resolve_project(
        project_name=params.project_name,
        create_if_missing=True,
        **project_metadata
    )
    
    print(f"Creating scan with Git context for baseline detection...")
    scan_code, _ = workbench.resolve_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=True,
        params=params,
        **scan_metadata
    )
    
    return project_code, scan_code

def _validate_bazel_environment(params: argparse.Namespace) -> None:
    """
    Validate that Bazel is properly installed and the workspace is valid.
    
    Args:
        params: Command line parameters
        
    Raises:
        ValidationError: If Bazel is not available or workspace is invalid
    """
    # Check Bazel installation
    bazel_available, bazel_message = BazelUtils.check_bazel_installation()
    if not bazel_available:
        raise ValidationError(f"Bazel is not properly configured: {bazel_message}")
    
    print(f"✓ Bazel found: {bazel_message}")
    
    # Validate workspace
    is_workspace, workspace_file = BazelUtils.detect_bazel_workspace(params.workspace_path)
    if not is_workspace:
        raise ValidationError(f"Not a valid Bazel workspace: {params.workspace_path}")
    
    print(f"✓ Bazel workspace detected: {workspace_file}")
    
    # Get workspace name for informational purposes
    workspace_name = BazelUtils.get_workspace_name(params.workspace_path)
    print(f"✓ Workspace name: {workspace_name}")

def _handle_target_discovery(params: argparse.Namespace) -> bool:
    """
    Handle the --discover-targets mode.
    
    Args:
        params: Command line parameters
        
    Returns:
        bool: True if discovery completed successfully
    """
    print("\n--- Discovering Bazel Targets ---")
    
    try:
        # Validate workspace
        is_workspace, workspace_file = BazelUtils.detect_bazel_workspace(params.workspace_path)
        if not is_workspace:
            print(f"Error: {params.workspace_path} is not a valid Bazel workspace")
            return False
        
        print(f"Workspace: {params.workspace_path} ({workspace_file})")
        workspace_name = BazelUtils.get_workspace_name(params.workspace_path)
        print(f"Workspace Name: {workspace_name}")
        
        # Discover deployable targets
        print("\nDiscovering deployable targets...")
        targets = BazelUtils.discover_deployable_targets(params.workspace_path, params.bazel_query_options)
        
        if not targets:
            print("\nNo deployable targets found.")
            print("This workspace might not contain applications or the targets use custom rules.")
            print("\nYou can still scan the workspace using:")
            print(f"  workbench-cli scan-bazel --workspace-path {params.workspace_path} --target '//...'")
            return True
        
        print(f"\nFound {len(targets)} deployable targets:")
        print("")
        
        # Group by category for better display
        by_category = {}
        for target in targets:
            category = target["category"]
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(target)
        
        for category, cat_targets in by_category.items():
            print(f"📦 {category.upper()} TARGETS ({len(cat_targets)}):")
            for target in cat_targets:
                print(f"  {target['target']} ({target['kind']})")
                print(f"    → Suggested Project: {target['suggested_project']}")
                print(f"    → Suggested Scan: {target['suggested_scan']}")
                print("")
        
        print("🚀 GETTING STARTED:")
        print("Choose a target and run:")
        if targets:
            example_target = targets[0]
            print(f"  workbench-cli scan-bazel \\")
            print(f"    --workspace-path {params.workspace_path} \\")
            print(f"    --target '{example_target['target']}' \\")
            print(f"    --project-name '{example_target['suggested_project']}' \\")
            print(f"    --scan-name '{example_target['suggested_scan']}'")
        
        return True
        
    except Exception as e:
        logger.error(f"Target discovery failed: {e}", exc_info=True)
        print(f"Error during target discovery: {e}")
        return False

def _handle_dry_run(params: argparse.Namespace) -> bool:
    """
    Handle the --dry-run mode.
    
    Args:
        params: Command line parameters
        
    Returns:
        bool: True if dry run completed successfully
    """
    print("\n--- Bazel Scan Estimation (Dry Run) ---")
    
    try:
        # Validate workspace
        is_workspace, workspace_file = BazelUtils.detect_bazel_workspace(params.workspace_path)
        if not is_workspace:
            print(f"Error: {params.workspace_path} is not a valid Bazel workspace")
            return False
        
        print(f"Workspace: {params.workspace_path} ({workspace_file})")
        workspace_name = BazelUtils.get_workspace_name(params.workspace_path)
        print(f"Target Pattern: {params.target}")
        
        # Estimate scan scope
        print("\nAnalyzing scope...")
        estimation = BazelUtils.estimate_scan_scope(params.workspace_path, params.target, params.bazel_query_options)
        
        print(f"\n📊 SCAN ESTIMATION RESULTS:")
        print(f"  Target Pattern: {estimation['target_pattern']}")
        print(f"  Targets Found: {estimation['targets_found']:,}")
        print(f"  Estimated Files: {estimation['estimated_files']:,}")
        print(f"  Estimated Size: {estimation['estimated_size_mb']} MB")
        print(f"  Packages Involved: {len(estimation['packages_involved'])}")
        if estimation['packages_involved']:
            print(f"    {', '.join(estimation['packages_involved'][:5])}{'...' if len(estimation['packages_involved']) > 5 else ''}")
        print(f"  External Dependencies: {'Yes' if estimation['external_deps_found'] else 'No'}")
        
        # Provide recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        approach = estimation['recommended_approach']
        if approach == "staged_onboarding":
            print(f"  🔄 Large workspace detected. Consider staged onboarding:")
            print(f"     1. Start with specific application: --target '//apps/frontend/...'")
            print(f"     2. Expand gradually: --target '//apps/... + //services/...'")
            print(f"     3. Full scan when ready: --target '//...'")
        elif approach == "targeted_scan":
            print(f"  🎯 Medium-sized workspace. Consider targeted scanning:")
            print(f"     → Focus on specific applications or services")
            print(f"     → Use discovery mode: --discover-targets")
        else:
            print(f"  ✅ Good size for full workspace scanning")
        
        if estimation['external_deps_found']:
            print(f"  📦 External dependencies detected - these will be included in dependency analysis")
        
        # Estimate time
        files = estimation['estimated_files']
        if files < 1000:
            time_estimate = "1-3 minutes"
        elif files < 5000:
            time_estimate = "3-8 minutes"
        elif files < 20000:
            time_estimate = "8-20 minutes"
        else:
            time_estimate = "20+ minutes"
        
        print(f"  ⏱️  Estimated Scan Time: {time_estimate}")
        
        print(f"\n🚀 TO PROCEED WITH ACTUAL SCAN:")
        print(f"  workbench-cli scan-bazel \\")
        print(f"    --workspace-path {params.workspace_path} \\")
        print(f"    --target '{params.target}' \\")
        print(f"    --project-name '<YOUR_PROJECT_NAME>' \\")
        print(f"    --scan-name '<YOUR_SCAN_NAME>'")
        
        return True
        
    except Exception as e:
        logger.error(f"Dry run failed: {e}", exc_info=True)
        print(f"Error during dry run: {e}")
        return False

def _auto_suggest_missing_names(params: argparse.Namespace) -> None:
    """
    Auto-suggest project and scan names if they are not provided.
    Modifies params in-place.
    
    Args:
        params: Command line parameters
    """
    if not params.project_name or not params.scan_name:
        print("\n--- Auto-Suggesting Missing Names ---")
        
        try:
            # Validate workspace
            is_workspace, workspace_file = BazelUtils.detect_bazel_workspace(params.workspace_path)
            if not is_workspace:
                raise ValueError(f"{params.workspace_path} is not a valid Bazel workspace")
            
            # Generate suggestions only for missing names
            if not params.project_name:
                suggested_project = BazelUtils.suggest_project_name(params.workspace_path, params.target)
                params.project_name = suggested_project
                print(f"📝 Auto-suggested project name: {suggested_project}")
            
            if not params.scan_name:
                suggested_scan = BazelUtils.suggest_scan_name(params.workspace_path, params.target, params.baseline_commit)
                params.scan_name = suggested_scan
                print(f"📝 Auto-suggested scan name: {suggested_scan}")
                
        except Exception as e:
            logger.error(f"Name auto-suggestion failed: {e}", exc_info=True)
            raise WorkbenchCLIError(f"Failed to auto-suggest names: {e}")

@handler_error_wrapper
def handle_scan_bazel(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan-bazel' command. Analyzes a Bazel workspace using Bazel query capabilities.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        bool: True if the operation completed successfully
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    
    # Initialize timing dictionary
    durations = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
        "bazel_analysis": 0.0,
        "archive_creation": 0.0
    }
    
    # Handle discovery and analysis modes (these don't require API access)
    if getattr(params, 'discover_targets', False):
        return _handle_target_discovery(params)
    
    if getattr(params, 'dry_run', False):
        return _handle_dry_run(params)
    
    # Auto-suggest project and scan names if not provided
    _auto_suggest_missing_names(params)
    
    # Validate Bazel environment early
    print("\n--- Validating Bazel Environment ---")
    _validate_bazel_environment(params)
    
    # Validate ID reuse source early to WARN if it cannot be validated
    api_reuse_type = None
    resolved_specific_code_for_reuse = None
    if getattr(params, 'id_reuse', False):
        print("\nValidating ID reuse source before proceeding...")
        try:
            api_reuse_type, resolved_specific_code_for_reuse = validate_reuse_source(workbench, params)
            print(f"Successfully validated ID reuse source.")
        except Exception as e:
            # Log the error but don't show additional warnings since validate_reuse_source already shows them
            logger.warning(f"ID reuse validation failed ({type(e).__name__}): {e}. Continuing without ID reuse.")
            # Disable ID reuse for this scan
            params.id_reuse = False
    
    # Resolve project and scan (find or create)
    print("\nChecking if the Project and Scan exist or need to be created...")
    project_code, scan_code = _get_project_and_scan_codes(workbench, params)
    
    print(f"Processing Bazel scan for scan '{scan_code}' in project '{project_code}'...")

    # Ensure scan is compatible with the current operation
    ensure_scan_compatibility(workbench, params, scan_code)

    # Ensure scan is idle before starting Bazel analysis
    print("\nEnsuring the Scan is idle before starting Bazel analysis...")
    workbench.ensure_scan_is_idle(scan_code, params, ["EXTRACT_ARCHIVES", "SCAN", "DEPENDENCY_ANALYSIS"])

    # Clear existing scan content
    print("\nClearing existing scan content...")
    try:
        workbench.remove_uploaded_content(scan_code, "")
        print("Successfully cleared existing scan content.")
    except Exception as e:
        logger.warning(f"Failed to clear existing scan content: {e}")
        print(f"Warning: Could not clear existing scan content: {e}")
        print("Continuing with Bazel analysis...")

    # Perform Bazel analysis to determine files to scan
    print("\n--- Analyzing Bazel Workspace ---")
    
    import time
    bazel_start_time = time.monotonic()
    
    try:
        # Determine which files to scan using Bazel query
        files_to_scan = BazelUtils.get_files_to_scan(
            workspace_path=params.workspace_path,
            target=params.target,
            baseline_commit=params.baseline_commit,
            query_options=params.bazel_query_options
        )
        
        bazel_end_time = time.monotonic()
        durations["bazel_analysis"] = bazel_end_time - bazel_start_time
        
        if not files_to_scan:
            print("\nNo files found to scan. This may happen with incremental scans when no relevant changes are detected.")
            print("Scan completed successfully (no work needed).")
            return True
        
        print(f"\nBazel analysis complete. Found {len(files_to_scan)} files to scan.")
        if params.baseline_commit:
            print(f"Incremental scan from baseline: {params.baseline_commit}")
        else:
            print("Full workspace scan.")
            
    except Exception as e:
        logger.error(f"Bazel analysis failed: {e}", exc_info=True)
        raise ProcessError(f"Bazel analysis failed: {e}")

    # Create filtered archive containing only the files we want to scan
    print("\n--- Creating Filtered Archive ---")
    
    archive_start_time = time.monotonic()
    
    try:
        # Create a custom archive with only the selected files
        archive_path = _create_filtered_bazel_archive(
            workspace_path=params.workspace_path,
            files_to_include=files_to_scan
        )
        
        archive_end_time = time.monotonic()
        durations["archive_creation"] = archive_end_time - archive_start_time
        
        print(f"Successfully created filtered archive: {os.path.basename(archive_path)}")
        
    except Exception as e:
        logger.error(f"Archive creation failed: {e}", exc_info=True)
        raise ProcessError(f"Failed to create archive: {e}")

    # Upload the filtered archive
    print("\n--- Uploading Filtered Archive ---")
    try:
        workbench.upload_scan_target(scan_code, archive_path)
        print(f"Successfully uploaded filtered archive to Workbench.")
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        raise ProcessError(f"Failed to upload archive: {e}")
    finally:
        # Clean up the temporary archive
        try:
            if os.path.exists(archive_path):
                os.remove(archive_path)
                logger.debug(f"Cleaned up temporary archive: {archive_path}")
        except Exception as cleanup_error:
            logger.warning(f"Failed to cleanup archive: {cleanup_error}")

    # Handle archive extraction (no archives in our filtered upload, but keep for consistency)
    print("\nExtracting Uploaded Archive...")
    extraction_triggered = workbench.extract_archives(scan_code, False, False)  # No recursive extraction needed
    
    if extraction_triggered:
        if workbench._is_status_check_supported(scan_code, "EXTRACT_ARCHIVES"):
            try:
                extraction_status_data, extraction_duration = workbench.wait_for_archive_extraction(
                    scan_code,
                    params.scan_number_of_tries,
                    5
                )
                durations["extraction_duration"] = extraction_duration
            except Exception as e:
                logger.error(f"Archive extraction issue: {e}")
                print(f"\nWARNING: Archive extraction encountered an issue: {e}")
                print("Attempting to continue with the scan process...")
        else:
            print("Archive extraction status check not supported. Waiting 3 seconds before continuing...")
            time.sleep(3)
    else:
        print("No archives to extract. Continuing with scan...")

    # Verify scan can start
    workbench.ensure_scan_is_idle(scan_code, params, ["EXTRACT_ARCHIVES", "SCAN", "DEPENDENCY_ANALYSIS"])
    
    # Determine which scan operations to run
    scan_operations = determine_scans_to_run(params)
    
    # Run KB Scan
    scan_completed = False
    da_completed = False
    
    try:
        # Handle dependency analysis only mode
        if not scan_operations["run_kb_scan"] and scan_operations["run_dependency_analysis"]:
            print("\nStarting Dependency Analysis only (skipping KB scan)...")
            workbench.start_dependency_analysis(scan_code, import_only=False)
            
            # Handle no-wait mode
            if getattr(params, 'no_wait', False):
                print("Dependency Analysis has been started.")
                print("\nExiting without waiting for completion (--no-wait mode).")
                print("You can check the status later using the 'show-results' command.")
                print_operation_summary(params, True, project_code, scan_code, durations)
                return True
            
            # Wait for dependency analysis to complete
            try:
                da_status_data, da_duration = workbench.wait_for_scan_to_finish(
                    "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time
                )
                
                # Store the duration
                durations["dependency_analysis"] = da_duration
                da_completed = True
                
                # We didn't run a KB scan but we'll mark it as completed for result processing
                scan_completed = True
                
                # Print operation summary
                print_operation_summary(params, da_completed, project_code, scan_code, durations)
                
                # Show results
                fetch_display_save_results(workbench, params, scan_code)
                
                return True
                
            except Exception as e:
                logger.error(f"Error waiting for dependency analysis to complete: {e}", exc_info=True)
                print(f"\nError: Dependency analysis failed: {e}")
                return False
        
        # Start the KB scan (only if run_kb_scan is True)
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
            
            # Check if no-wait mode is enabled - if so, exit early
            if getattr(params, 'no_wait', False):
                print("\nKB Scan started successfully.")
                if scan_operations["run_dependency_analysis"]:
                    print("Dependency Analysis will automatically start after scan completion.")
                
                print("\nExiting without waiting for completion (--no-wait mode).")
                print("You can check the scan status later using the 'show-results' command.")
                print_operation_summary(params, True, project_code, scan_code, durations)
                return True
            else:
                # Wait for KB scan to finish and get duration
                kb_status_data, kb_duration = workbench.wait_for_scan_to_finish(
                    "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
                )
                
                # Record KB scan duration
                durations["kb_scan"] = kb_duration
                scan_completed = True
                
                # If dependency analysis was requested, wait for it to complete
                if scan_completed and scan_operations["run_dependency_analysis"]:
                    print("\nWaiting for Dependency Analysis to complete...")
                    try:
                        da_status_data, da_duration = workbench.wait_for_scan_to_finish(
                            "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time,
                        )
                        
                        # Record DA duration
                        durations["dependency_analysis"] = da_duration
                        da_completed = True
                    except Exception as e:
                        logger.warning(f"Error waiting for dependency analysis to complete: {e}")
                        print(f"\nWarning: Error waiting for dependency analysis to complete: {e}")
                        da_completed = False
    
    except (ProcessTimeoutError, ProcessError) as e:
        scan_completed = False
        raise
    except Exception as e:
        scan_completed = False
        logger.error(f"Error during KB scan for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchCLIError(f"Error during KB scan: {e}", details={"error": str(e)}) from e

    # Show scan summary and operation details
    print_operation_summary(params, da_completed, project_code, scan_code, durations)

    # Show scan results if any were requested
    if any([params.show_licenses, params.show_components, params.show_dependencies,
            params.show_scan_metrics, params.show_policy_warnings, params.show_vulnerabilities]):
        fetch_display_save_results(workbench, params, scan_code)

    return True

def _create_filtered_bazel_archive(workspace_path: str, files_to_include: Set[str]) -> str:
    """
    Create a ZIP archive containing only the specified files from the Bazel workspace.
    
    Args:
        workspace_path: Path to the Bazel workspace
        files_to_include: Set of file paths relative to workspace to include
        
    Returns:
        str: Path to the created archive
        
    Raises:
        ProcessError: If archive creation fails
    """
    import tempfile
    import zipfile
    
    try:
        # Create temporary directory for the archive
        temp_dir = tempfile.mkdtemp(prefix="workbench_bazel_upload_")
        archive_name = "bazel_filtered_upload.zip"
        archive_path = os.path.join(temp_dir, archive_name)
        
        logger.debug(f"Creating filtered Bazel archive: {archive_path}")
        logger.debug(f"Including {len(files_to_include)} files")
        
        files_added = 0
        files_skipped = 0
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
            for rel_file_path in files_to_include:
                abs_file_path = os.path.join(workspace_path, rel_file_path)
                
                # Check if file exists and is readable
                if not os.path.exists(abs_file_path):
                    logger.debug(f"Skipping non-existent file: {rel_file_path}")
                    files_skipped += 1
                    continue
                
                if not os.path.isfile(abs_file_path):
                    logger.debug(f"Skipping non-regular file: {rel_file_path}")
                    files_skipped += 1
                    continue
                
                try:
                    zipf.write(abs_file_path, rel_file_path)
                    files_added += 1
                    
                    if files_added % 100 == 0:  # Progress logging
                        logger.debug(f"Added {files_added} files to archive...")
                        
                except Exception as e:
                    files_skipped += 1
                    logger.warning(f"Failed to add {rel_file_path} to archive: {e}")
                    continue
        
        # Verify the archive was created successfully
        if not os.path.exists(archive_path) or os.path.getsize(archive_path) == 0:
            raise ProcessError("Archive creation failed - file is missing or empty")
        
        archive_size_mb = os.path.getsize(archive_path) / (1024 * 1024)
        logger.info(f"Filtered archive created successfully: {archive_path}")
        logger.info(f"Archive size: {archive_size_mb:.1f}MB")
        logger.info(f"Files added: {files_added}, Files skipped: {files_skipped}")
        
        print(f"Created archive with {files_added} files ({archive_size_mb:.1f}MB)")
        if files_skipped > 0:
            print(f"Skipped {files_skipped} files (missing or invalid)")
        
        return archive_path
        
    except Exception as e:
        logger.error(f"Failed to create filtered archive: {e}", exc_info=True)
        # Clean up on failure
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as cleanup_err:
                logger.warning(f"Failed to cleanup temp directory: {cleanup_err}")
        raise ProcessError(f"Archive creation failed: {e}") from e 