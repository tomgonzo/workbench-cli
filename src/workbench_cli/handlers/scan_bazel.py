# workbench_cli/handlers/scan_bazel.py

import os
import logging
import argparse
import zipfile
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
from ..utilities.git_utils import GitUtils
from ..utilities.bazel_utils_modules.bazel_core import BazelCore

if TYPE_CHECKING:
    from ..api import WorkbenchAPI

logger = logging.getLogger("workbench-cli")

def _get_project_and_scan_codes(workbench: "WorkbenchAPI", params: argparse.Namespace) -> tuple[str, str]:
    """
    Resolve project and scan codes for bzlmod Bazel scan with module-specific metadata.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        tuple[str, str]: Project code and scan code
    """
    # Generate bzlmod-specific metadata for project
    project_metadata = BazelUtils.generate_project_metadata(params.workspace_path, params.target)
    
    # Generate scan metadata with Git context and module version for baseline detection
    scan_metadata = BazelUtils.generate_scan_metadata(
        workspace_path=params.workspace_path,
        target=params.target,
        baseline_commit=getattr(params, 'baseline_commit', None)
    )
    
    print(f"Creating project with bzlmod metadata: {project_metadata['product_name']}")
    project_code = workbench.resolve_project(
        project_name=params.project_name,
        create_if_missing=True,
        **project_metadata
    )
    
    print(f"Creating scan with module and Git context for baseline detection...")
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
    Validate that Bazel is properly installed and the workspace is a valid bzlmod workspace.
    
    Args:
        params: Command line parameters
        
    Raises:
        ValidationError: If Bazel is not available or workspace is not bzlmod
    """
    # Check Bazel installation
    bazel_available, bazel_message = BazelUtils.check_bazel_installation()
    if not bazel_available:
        raise ValidationError(f"Bazel is not properly configured: {bazel_message}")
    
    print(f"✓ Bazel found: {bazel_message}")
    
    # Validate bzlmod workspace (this will raise helpful errors for legacy WORKSPACE)
    try:
        BazelUtils.validate_workspace(params.workspace_path)
        print(f"✓ Valid bzlmod workspace detected with MODULE.bazel")
    except ValidationError as e:
        # BazelCore.validate_workspace provides helpful error messages for legacy workspaces
        raise e
    
    # Get module name and version for informational purposes
    module_name = BazelUtils.get_workspace_name(params.workspace_path)
    module_version = BazelUtils.get_module_version(params.workspace_path)
    
    print(f"✓ Module name: {module_name}")
    if module_version:
        is_dev = BazelUtils.is_development_version(module_version)
        dev_indicator = " (development)" if is_dev else " (release)"
        print(f"✓ Module version: {module_version}{dev_indicator}")
    else:
        print(f"ℹ️  Module version: Not specified in MODULE.bazel")

def _handle_target_discovery(params: argparse.Namespace) -> bool:
    """
    Handle the --discover-targets mode for bzlmod workspaces.
    
    Args:
        params: Command line parameters
        
    Returns:
        bool: True if discovery completed successfully
    """
    print("\n--- Discovering Bzlmod Bazel Targets ---")
    
    try:
        # Validate bzlmod workspace
        try:
            BazelUtils.validate_workspace(params.workspace_path)
        except ValidationError as e:
            print(f"Error: {e}")
            return False
        
        module_name = BazelUtils.get_workspace_name(params.workspace_path)
        module_version = BazelUtils.get_module_version(params.workspace_path)
        
        print(f"Bzlmod Module: {module_name}")
        if module_version:
            is_dev = BazelUtils.is_development_version(module_version)
            dev_indicator = " (development)" if is_dev else " (release)"
            print(f"Module Version: {module_version}{dev_indicator}")
        print(f"Workspace Path: {params.workspace_path}")
        
        # Discover scannable targets (expanded beyond just deployable)
        print("\nDiscovering scannable targets...")
        targets = BazelUtils.discover_deployable_targets(params.workspace_path, params.bazel_query_options)
        
        if not targets:
            print("\nNo scannable targets found.")
            print("This might be an empty module or all targets use unsupported custom rules.")
            print("\nYou can still scan the entire module using:")
            print(f"  workbench-cli scan-bazel --workspace-path {params.workspace_path} --target '//...'")
            return True
        
        print(f"\nFound {len(targets)} scannable targets:")
        print("")
        
        # Group by category for better display
        by_category = {}
        for target in targets:
            category = target["category"]
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(target)
        
        # Display categories with appropriate emojis and descriptions
        category_display = {
            "executable": ("🚀", "EXECUTABLE TARGETS", "Ready-to-run applications and binaries"),
            "library": ("📚", "LIBRARY TARGETS", "Reusable code libraries and modules"),
            "test": ("🧪", "TEST TARGETS", "Test suites and test code"),
            "container": ("🐳", "CONTAINER TARGETS", "Container images and deployment configs"),
            "proto": ("📄", "PROTOCOL TARGETS", "Protocol buffer definitions and generated code"),
            "web": ("🌐", "WEB TARGETS", "Frontend and web application code"),
            "tool": ("🔧", "TOOL TARGETS", "Build tools and utilities")
        }
        
        for category, cat_targets in by_category.items():
            emoji, title, description = category_display.get(category, ("📦", f"{category.upper()} TARGETS", ""))
            print(f"{emoji} {title} ({len(cat_targets)})")
            if description:
                print(f"   {description}")
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
            
        print("\n💡 TIP: You can also scan multiple targets or the entire workspace:")
        print(f"  # Scan all library targets")
        print(f"  workbench-cli scan-bazel --workspace-path {params.workspace_path} --target 'kind(\".*_library\", //...)'")
        print(f"  # Scan everything")
        print(f"  workbench-cli scan-bazel --workspace-path {params.workspace_path} --target '//...'")
        
        return True
        
    except Exception as e:
        logger.error(f"Target discovery failed: {e}", exc_info=True)
        print(f"Error during target discovery: {e}")
        return False

def _handle_dry_run(params: argparse.Namespace) -> bool:
    """
    Handle the --dry-run mode for bzlmod workspaces.
    
    Args:
        params: Command line parameters
        
    Returns:
        bool: True if dry run completed successfully
    """
    print("\n--- Bzlmod Bazel Scan Estimation (Dry Run) ---")
    
    try:
        # Validate bzlmod workspace
        try:
            BazelUtils.validate_workspace(params.workspace_path)
        except ValidationError as e:
            print(f"Error: {e}")
            return False
        
        module_name = BazelUtils.get_workspace_name(params.workspace_path)
        module_version = BazelUtils.get_module_version(params.workspace_path)
        
        print(f"Bzlmod Module: {module_name}")
        if module_version:
            is_dev = BazelUtils.is_development_version(module_version)
            dev_indicator = " (development)" if is_dev else " (release)"
            print(f"Module Version: {module_version}{dev_indicator}")
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
        print(f"  Bzlmod Workspace: {'Yes' if estimation.get('bzlmod', False) else 'No'}")
        
        # Show module version information if available
        if 'module_version' in estimation:
            is_dev_text = " (development)" if estimation.get('is_development', False) else " (release)"
            print(f"  Module Version: {estimation['module_version']}{is_dev_text}")
        
        # Show delta scan potential
        print(f"\n🔄 DELTA SCAN ANALYSIS:")
        is_git_repo = GitUtils.is_git_repository(params.workspace_path)
        delta_scan_requested = getattr(params, 'delta_scan', False)
        print(f"  Git Repository: {'Yes' if is_git_repo else 'No'}")
        print(f"  --scan-delta Flag: {'Yes' if delta_scan_requested else 'No'}")
        
        if delta_scan_requested and is_git_repo:
            git_info = GitUtils.get_git_version_info(params.workspace_path)
            print(f"  Current Commit: {git_info['short_commit'] or 'Unknown'}")
            print(f"  Current Branch: {git_info['branch'] or 'Detached HEAD'}")
            print(f"  Auto-Baseline: Will be detected from existing scan description")
            print(f"  Scan Type: Delta (first run establishes baseline, subsequent runs incremental)")
            
            print(f"  💡 Benefits: Only changed files will be processed")
            print(f"     → Typically 5-10x faster for small changes")
            print(f"     → Fully automatic baseline tracking between delta scans")
            print(f"     → Automatic duplicate detection (skips if commit already analyzed)")
        elif delta_scan_requested:
            print(f"  🔄 Delta scan requested but not in Git repository")
            print(f"  Scan Type: Full scan (fallback)")
        elif is_git_repo:
            print(f"  🔄 Delta scanning available with --scan-delta flag")
            print(f"  Scan Type: Full scan (no --scan-delta flag)")
        else:
            print(f"  🔄 Delta scans not available (requires Git repository and --scan-delta flag)")
            print(f"  Scan Type: Full scan")
        
        # Provide recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        approach = estimation['recommended_approach']
        if approach == "staged_onboarding":
            print(f"  🔄 Large module detected. Consider staged onboarding:")
            print(f"     1. Start with specific application: --target '//apps/frontend/...'")
            print(f"     2. Expand gradually: --target '//apps/... + //services/...'")
            print(f"     3. Full scan when ready: --target '//...'")
        elif approach == "targeted_scan":
            print(f"  🎯 Medium-sized module. Consider targeted scanning:")
            print(f"     → Focus on specific applications or services")
            print(f"     → Use discovery mode: --discover-targets")
        else:
            print(f"  ✅ Good size for full module scanning")
        
        if estimation['external_deps_found']:
            print(f"  📦 External dependencies detected - these will be included in dependency analysis")
            print(f"     → Bzlmod provides automatic transitive dependency resolution")
        
        # Show build-aware dependency analysis information
        include_resolved_deps = getattr(params, 'include_resolved_deps', True)
        print(f"\n🔍 BUILD-AWARE DEPENDENCY ANALYSIS:")
        print(f"  Include Resolved Dependencies: {'Yes' if include_resolved_deps else 'No'}")
        if include_resolved_deps:
            print(f"  📈 This will include actual resolved dependency artifacts from Bazel's external/ directory")
            print(f"  ✅ Provides more accurate dependency analysis than manifest-only approach")
            print(f"  ⏱️  Note: Initial dependency resolution may add 1-3 minutes to scan time")
            if estimation['external_deps_found']:
                print(f"  📦 Detected bzlmod external dependencies will be resolved and included")
            else:
                print(f"  ℹ️  No external dependencies detected in this target")
        else:
            print(f"  📋 Will use traditional manifest-based dependency analysis only")
            print(f"  ⚠️  May miss some transitive dependencies resolved by bzlmod")
        
        # Estimate time
        files = estimation['estimated_files']
        base_time_minutes = 0
        if files < 1000:
            base_time_minutes = 2
        elif files < 5000:
            base_time_minutes = 5
        elif files < 20000:
            base_time_minutes = 14
        else:
            base_time_minutes = 30
            
        # Add time for dependency resolution if enabled
        if include_resolved_deps and estimation['external_deps_found']:
            base_time_minutes += 2  # Add 2 minutes for dependency resolution
            
        if base_time_minutes <= 3:
            time_estimate = f"{base_time_minutes} minutes"
        elif base_time_minutes <= 10:
            time_estimate = f"{base_time_minutes-2}-{base_time_minutes+3} minutes"
        else:
            time_estimate = f"{base_time_minutes}+ minutes"
        
        print(f"  ⏱️  Estimated Scan Time: {time_estimate}")
        
        print(f"\n🚀 TO PROCEED WITH ACTUAL SCAN:")
        print(f"  workbench-cli scan-bazel \\")
        print(f"    --workspace-path {params.workspace_path} \\")
        print(f"    --target '{params.target}' \\")
        
        # Add project/scan name suggestions based on bzlmod
        suggested_project = BazelUtils.suggest_project_name(params.workspace_path, params.target)
        suggested_scan = BazelUtils.suggest_scan_name_with_bzlmod(params.workspace_path, params.target)
        
        print(f"    --project-name '{suggested_project}' \\")
        print(f"    --scan-name '{suggested_scan}'")
        
        if delta_scan_requested and is_git_repo:
            print(f"    --scan-delta")
        
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
                suggested_scan = BazelUtils.suggest_scan_name(params.workspace_path, params.target, getattr(params, 'baseline_commit', None))
                params.scan_name = suggested_scan
                print(f"📝 Auto-suggested scan name: {suggested_scan}")
                
        except Exception as e:
            logger.error(f"Name auto-suggestion failed: {e}", exc_info=True)
            raise WorkbenchCLIError(f"Failed to auto-suggest names: {e}")

@handler_error_wrapper
def handle_scan_bazel(workbench: "WorkbenchAPI", params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan-bazel' command. Analyzes bzlmod Bazel workspaces using Bazel query capabilities.
    
    This command only supports modern bzlmod workspaces with MODULE.bazel files.
    Legacy WORKSPACE-based projects are not supported - users should migrate to bzlmod first.
    
    Supports automatic delta scanning with the --scan-delta flag:
    - First delta scan: Establishes baseline and performs full scan
    - Subsequent delta scans: Automatically detects baseline and scans only changed files
    - Without --scan-delta: Always performs full scan (no baseline tracking)
    - Fully automatic: No manual baseline management required
    
    Bzlmod-specific features:
    - MODULE.bazel version-aware scan naming
    - Automatic transitive dependency resolution via bzlmod
    - Enhanced external dependency analysis using Bazel's resolved artifacts
    
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
    
    # Add environment health check with recommendations
    if not getattr(params, 'skip_env_check', False):
        print("\n--- Environment Health Check ---")
        env_status = BazelCore.validate_environment(params.workspace_path)
        
        print(f"🏥 Environment Health: {env_status['health_score'].upper()}")
        
        if env_status["warnings"]:
            print("⚠️  Warnings:")
            for warning in env_status["warnings"]:
                print(f"   • {warning}")
        
        if env_status["errors"]:
            print("❌ Errors:")
            for error in env_status["errors"]:
                print(f"   • {error}")
            
            if not env_status["is_valid"]:
                print("\n🛑 Environment validation failed. Scan may not work reliably.")
                print("Consider using emergency filesystem scan or add --skip-env-check to bypass")
                # Don't fail completely - let progressive degradation handle it
        
        if env_status["recommendations"]:
            print("💡 Recommendations:")
            for rec in env_status["recommendations"]:
                print(f"   • {rec}")
        
        # Show resource status for transparency
        if env_status.get("resource_status"):
            res = env_status["resource_status"]
            if "disk" in res and "free_mb" in res["disk"]:
                print(f"💾 Available disk space: {res['disk']['free_mb']}MB")
            if "workspace_size" in res and "file_count" in res["workspace_size"]:
                file_count = res["workspace_size"]["file_count"]
                estimated = res["workspace_size"].get("estimated", False)
                print(f"📁 Workspace size: {file_count}{'+ (estimated)' if estimated else ''} files")
        
        print()  # Empty line for spacing
    else:
        print("\n⚠️  Environment health check skipped (--skip-env-check)")
        print()
    
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

    # Handle delta scan (incremental) detection
    original_scan_type = "full"
    if getattr(params, 'delta_scan', False) and GitUtils.is_git_repository(params.workspace_path):
        print("\n--- Delta Scan Requested ---")
        try:
            # Always try to detect baseline from existing scan description
            print("🔍 Looking for existing baseline from previous scans...")
            detected_baseline = GitUtils.setup_incremental_scan_from_existing(
                workbench, params.workspace_path, scan_code, params.target
            )
            
            if detected_baseline:
                # Check if current commit is the same as baseline (already analyzed)
                current_commit = GitUtils.get_current_commit_hash(params.workspace_path)
                if current_commit and current_commit == detected_baseline:
                    print(f"✅ Current commit {current_commit[:8]}... has already been analyzed")
                    print("📋 No changes detected since last scan - scan not needed")
                    print("💡 To force a re-scan, run without --scan-delta flag")
                    return True  # Exit gracefully - no scan needed
                
                params.baseline_commit = detected_baseline
                original_scan_type = "delta"
                print(f"✅ Delta scan enabled - baseline: {detected_baseline[:8]}...")
            else:
                print("ℹ️  No previous baseline found")
                print("📋 Performing full scan to establish baseline for future delta scans")
                original_scan_type = "baseline"
                
        except Exception as e:
            logger.warning(f"Failed to setup delta scan: {e}")
            print("⚠️  Delta scan setup failed - performing full scan to establish baseline")
            original_scan_type = "baseline"
    elif getattr(params, 'delta_scan', False):
        print("⚠️  Delta scan requested but not in a Git repository - performing full scan")

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
    print("\n--- Analyzing Bzlmod Bazel Workspace ---")
    
    import time
    bazel_start_time = time.monotonic()
    
    try:
        # Determine which files to scan using Bazel query
        files_to_scan = BazelUtils.get_files_to_scan(
            workspace_path=params.workspace_path,
            target=params.target,
            baseline_commit=getattr(params, 'baseline_commit', None),
            query_options=params.bazel_query_options,
            include_resolved_deps=getattr(params, 'include_resolved_deps', True),
            exclude_dev_deps=getattr(params, 'exclude_dev_deps', False)
        )
        
        bazel_end_time = time.monotonic()
        durations["bazel_analysis"] = bazel_end_time - bazel_start_time
        
        if not files_to_scan:
            print("\nNo files found to scan. This may happen with incremental scans when no relevant changes are detected.")
            print("Scan completed successfully (no work needed).")
            return True
        
        print(f"\nBazel analysis complete. Found {len(files_to_scan)} files to scan.")
        baseline_commit = getattr(params, 'baseline_commit', None)
        if baseline_commit:
            print(f"Incremental scan from baseline: {baseline_commit}")
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
        # Clean up the temporary archive - moved to separate try-catch
        try:
            if archive_path and os.path.exists(archive_path):
                os.remove(archive_path)
                logger.debug(f"Cleaned up temporary archive: {archive_path}")
        except Exception as cleanup_error:
            logger.warning(f"Failed to cleanup archive: {cleanup_error}")
            # Don't re-raise cleanup errors - they shouldn't fail the whole operation

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
                
                # Update scan description for future delta scans (no-wait mode)
                if GitUtils.is_git_repository(params.workspace_path) and original_scan_type in ["delta", "baseline"]:
                    try:
                        GitUtils.update_scan_with_current_commit(
                            workbench, params.workspace_path, scan_code, params.target, 
                            original_scan_type, getattr(params, 'baseline_commit', None)
                        )
                        current_commit = GitUtils.get_current_commit_hash(params.workspace_path, short=True)
                        if original_scan_type == "baseline":
                            print(f"✅ Baseline established at commit: {current_commit}")
                        else:
                            print(f"✅ Scan baseline updated to current commit: {current_commit}")
                    except Exception as e:
                        logger.debug(f"Failed to update scan baseline in no-wait mode: {e}")
                
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
                print("You can check the status later using the 'show-results' command.")
                
                # Update scan description for future delta scans (no-wait mode)
                if GitUtils.is_git_repository(params.workspace_path) and original_scan_type in ["delta", "baseline"]:
                    try:
                        GitUtils.update_scan_with_current_commit(
                            workbench, params.workspace_path, scan_code, params.target, 
                            original_scan_type, getattr(params, 'baseline_commit', None)
                        )
                        current_commit = GitUtils.get_current_commit_hash(params.workspace_path, short=True)
                        if original_scan_type == "baseline":
                            print(f"✅ Baseline established at commit: {current_commit}")
                        else:
                            print(f"✅ Scan baseline updated to current commit: {current_commit}")
                    except Exception as e:
                        logger.debug(f"Failed to update scan baseline in no-wait mode: {e}")
                
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

    # Update scan description with current commit for future delta scans
    if GitUtils.is_git_repository(params.workspace_path):
        if original_scan_type in ["delta", "baseline"]:
            print("\n--- Updating Scan Baseline for Future Delta Scans ---")
            try:
                success = GitUtils.update_scan_with_current_commit(
                    workbench, 
                    params.workspace_path, 
                    scan_code, 
                    params.target,
                    original_scan_type,
                    getattr(params, 'baseline_commit', None)  # The baseline we used for this scan
                )
                if success:
                    current_commit = GitUtils.get_current_commit_hash(params.workspace_path, short=True)
                    if original_scan_type == "baseline":
                        print(f"✅ Baseline established at commit: {current_commit}")
                        print("   Future --scan-delta runs will be incremental from this point")
                    else:
                        print(f"✅ Scan baseline updated to current commit: {current_commit}")
                        print("   Future --scan-delta runs will continue to be incremental")
                else:
                    print("⚠️  Could not update scan baseline - future delta scans may not work optimally")
            except Exception as e:
                logger.warning(f"Failed to update scan baseline: {e}")
                print("⚠️  Could not update scan baseline - future delta scans may not work optimally")
        # For full scans (no --scan-delta), we don't update the baseline

    # Show scan summary and operation details
    print_operation_summary(params, da_completed, project_code, scan_code, durations)

    # Show scan results if any were requested
    if any([params.show_licenses, params.show_components, params.show_dependencies,
            params.show_scan_metrics, params.show_policy_warnings, params.show_vulnerabilities]):
        fetch_display_save_results(workbench, params, scan_code)

    return True

def _add_file_to_zip_with_normalized_timestamp(zipf: zipfile.ZipFile, file_path: str, arcname: str) -> None:
    """
    Add a file to ZIP archive with normalized timestamp to avoid ZIP timestamp issues.
    
    Args:
        zipf: ZipFile object to add file to
        file_path: Path to the source file
        arcname: Archive name for the file
    """
    import time
    
    # Read file content
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Create ZipInfo with normalized timestamp
    zip_info = zipfile.ZipInfo(filename=arcname)
    
    # Get original file stats
    file_stat = os.stat(file_path)
    
    # Normalize timestamp to ensure it's after 1980-01-01 
    # ZIP format uses DOS timestamp which starts from 1980
    min_time = time.mktime((1980, 1, 1, 0, 0, 0, 0, 0, -1))
    normalized_time = max(file_stat.st_mtime, min_time)
    
    # Set the normalized timestamp
    zip_info.date_time = time.localtime(normalized_time)[:6]
    
    # Preserve file permissions
    zip_info.external_attr = file_stat.st_mode << 16
    
    # Set compression method
    zip_info.compress_type = zipfile.ZIP_DEFLATED
    
    # Add file to archive with normalized info
    zipf.writestr(zip_info, file_data)

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
    
    try:
        # Get Bazel output_base for resolving external dependencies
        output_base = BazelUtils._get_output_base(workspace_path)
        
        # Check if we have external dependencies and validate output_base
        external_deps = {f for f in files_to_include if f.startswith('external/')}
        if external_deps and not output_base:
            logger.error(f"Found {len(external_deps)} external dependencies but could not determine Bazel output_base")
            logger.error("This will prevent external dependencies from being included in the scan")
            print(f"⚠️  Warning: {len(external_deps)} external dependencies may be skipped due to Bazel configuration issues")
        
        # Create temporary directory for the archive
        temp_dir = tempfile.mkdtemp(prefix="workbench_bazel_upload_")
        archive_name = "bazel_filtered_upload.zip"
        archive_path = os.path.join(temp_dir, archive_name)
        
        logger.debug(f"Creating filtered Bazel archive: {archive_path}")
        logger.debug(f"Including {len(files_to_include)} files ({len(external_deps)} external)")
        logger.debug(f"Bazel output_base: {output_base}")
        
        files_added = 0
        files_skipped = 0
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
            for rel_file_path in files_to_include:
                # Determine the absolute path based on whether it's an external dependency
                if rel_file_path.startswith('external/'):
                    # External dependency - look in output_base
                    if output_base:
                        # Remove 'external/' prefix and construct path in output_base
                        external_rel_path = rel_file_path[9:]  # Remove 'external/' prefix
                        abs_file_path = os.path.join(output_base, 'external', external_rel_path)
                    else:
                        logger.error(f"Cannot resolve external dependency without output_base: {rel_file_path}")
                        logger.error("This indicates a Bazel configuration issue. External dependencies may be missing.")
                        files_skipped += 1
                        continue
                else:
                    # Workspace file - look relative to workspace
                    abs_file_path = os.path.join(workspace_path, rel_file_path)
                
                # Check if file exists and is readable
                if not os.path.exists(abs_file_path):
                    # For external dependencies, this is more serious
                    if rel_file_path.startswith('external/'):
                        logger.warning(f"External dependency file not found: {rel_file_path} (expected at: {abs_file_path})")
                        logger.warning("This may indicate that Bazel dependencies haven't been resolved or downloaded yet.")
                    else:
                        logger.debug(f"Skipping non-existent workspace file: {rel_file_path}")
                    files_skipped += 1
                    continue
                
                if not os.path.isfile(abs_file_path):
                    logger.debug(f"Skipping non-regular file: {rel_file_path}")
                    files_skipped += 1
                    continue
                
                try:
                    # Use timestamp normalization to handle files with invalid timestamps
                    _add_file_to_zip_with_normalized_timestamp(zipf, abs_file_path, rel_file_path)
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
        
        # Check if we have a reasonable number of files
        if files_added == 0:
            raise ProcessError("Archive creation failed - no files were successfully added to the archive")
        
        archive_size_mb = os.path.getsize(archive_path) / (1024 * 1024)
        logger.info(f"Filtered archive created successfully: {archive_path}")
        logger.info(f"Archive size: {archive_size_mb:.1f}MB")
        logger.info(f"Files added: {files_added}, Files skipped: {files_skipped}")
        
        print(f"Created archive with {files_added} files ({archive_size_mb:.1f}MB)")
        if files_skipped > 0:
            print(f"Skipped {files_skipped} files (missing or invalid)")
            # If we skipped a significant portion of files, warn the user
            total_files = files_added + files_skipped
            skip_percentage = (files_skipped / total_files) * 100 if total_files > 0 else 0
            if skip_percentage > 20:  # More than 20% skipped
                print(f"⚠️  Warning: {skip_percentage:.1f}% of expected files were skipped")
                print("   This may indicate missing dependencies or configuration issues")
        
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