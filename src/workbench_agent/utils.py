# workbench_agent/utils.py

import os
import json
import time
import logging
import argparse
import re
import requests
import typing 
from typing import Generator, Optional, Dict, Any, List, Union, Tuple

# Import Workbench class for type hinting and accessing constants/methods if needed
# Use relative import within the package
if typing.TYPE_CHECKING:
    from .api import Workbench

from .exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError
)

# Assume logger is configured in main.py and get it
logger = logging.getLogger("log")

# --- Project and Scan Resolution ---

def _resolve_project(workbench: 'Workbench', project_name: str, create_if_missing: bool = False) -> str:
    """
    Resolve project name to project code.

    Args:
        workbench: The Workbench API client instance
        project_name: Name of the project
        create_if_missing: Whether to create the project if it doesn't exist

    Returns:
        str: Project code

    Raises:
        ProjectNotFoundError: If the project doesn't exist and create_if_missing is False
        ProjectExistsError: If the project exists and create_if_missing is True
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
    """
    try:
        # List all projects
        projects = workbench.list_projects()

        # Find project by name
        project = next((p for p in projects if p.get("project_name") == project_name), None)

        if project:
            project_code = project.get("project_code")
            if not project_code:
                 raise ApiError(f"Found project '{project_name}' but it is missing the 'code' attribute.", details=project)
            print(f"Found existing project '{project_name}' with code '{project_code}'.")
            return project_code
        else:
            # Project not found
            if create_if_missing:
                print(f"A Project called '{project_name}' was not found. Creating it...")
                try:
                    project_code = workbench.create_project(project_name)
                    print(f"Created new project '{project_name}' with code '{project_code}'.")
                    return project_code
                except ProjectExistsError:
                    logger.warning(f"Project '{project_name}' was not found initially, but creation failed because it exists. Re-fetching.")
                    projects = workbench.list_projects()
                    project = next((p for p in projects if p.get("project_name") == project_name), None)
                    if project and project.get("project_code"):
                        return project["project_code"]
                    else:
                        raise ApiError(f"Failed to resolve project '{project_name}' after creation conflict.")
                except (ApiError, NetworkError) as e:
                    raise ApiError(f"Failed to create project '{project_name}': {e}", details=getattr(e, 'details', None))

            else:
                # Not found and not creating
                raise ProjectNotFoundError(f"Project '{project_name}' not found and creation was not requested.")

    except (ProjectNotFoundError, ProjectExistsError, ApiError, NetworkError):
         raise
    except Exception as e:
        logger.error(f"Unexpected error resolving project '{project_name}': {e}", exc_info=True)
        raise WorkbenchAgentError(f"Unexpected error while resolving project '{project_name}': {e}",
                                details={"error": str(e)})

def _resolve_scan(workbench: 'Workbench', scan_name: str, project_name: Optional[str], create_if_missing: bool, params: argparse.Namespace) -> Tuple[str, int]:
    """
    Finds a scan by name, optionally creating it, handling both global and project scopes.
    (Docstring omitted for brevity in this example, but should be kept)
    """
    project_code: Optional[str] = None
    scan_list: List[Dict[str, Any]] = []
    search_context = ""

    if project_name:
        search_context = f"in project '{project_name}'"
        print(f"Looking for a scan called '{scan_name}' in the '{project_name}' project. (Create if missing: {create_if_missing})...")
        project_code = _resolve_project(workbench, project_name, create_if_missing=create_if_missing)
        try:
            scan_list = workbench.get_project_scans(project_code)
        except Exception as e:
            raise ApiError(f"Failed to list scans {search_context} while resolving '{scan_name}': {e}") from e
    else:
        search_context = "globally"
        print(f"Resolving scan '{scan_name}' globally (Create if missing: {create_if_missing})...")
        if create_if_missing:
            raise ConfigurationError("Cannot create a scan (create_if_missing=True) without specifying a --project-name.")
        try:
            scan_list = workbench.list_scans()
        except Exception as e:
            raise ApiError(f"Failed to list all scans while resolving '{scan_name}' globally: {e}") from e

    found_scans = [s for s in scan_list if s.get('name') == scan_name]

    if len(found_scans) == 1:
        scan_info = found_scans[0]
        scan_code = scan_info.get('code')
        scan_id_str = scan_info.get('id')
        resolved_project_code = scan_info.get('project_code', project_code)

        if not scan_code or scan_id_str is None:
            raise ValidationError(f"Found scan '{scan_name}' {search_context} but it's missing required 'code' or 'id' fields.")

        try:
            scan_id = int(scan_id_str)
            print(f"Successfully found the '{scan_name}' scan in the '{project_name}' project!")
            logger.debug(f"'{scan_name}' has code '{scan_code}' and ID {scan_id} (Project Code: {resolved_project_code}).")
            _ensure_scan_compatibility(params, scan_info, scan_code)
            return scan_code, scan_id
        except (ValueError, TypeError):
            raise ValidationError(f"Found scan '{scan_name}' {search_context} but its ID '{scan_id_str}' is not a valid integer.")
        except CompatibilityError:
            raise

    elif len(found_scans) > 1:
        project_codes = sorted(list(set(s.get('project_code', 'UnknownProject') for s in found_scans)))
        raise ValidationError(
            f"Multiple scans found globally with the name '{scan_name}' in projects: {', '.join(project_codes)}. "
            f"Please specify the --project-name to disambiguate."
        )
    else:
        if create_if_missing:
            print(f"Scan '{scan_name}' not found {search_context}. Creating it...")
            if not project_code:
                 raise ConfigurationError("Internal Error: project_code not resolved before scan creation attempt.")
            try:
                create_git_url = getattr(params, 'git_url', None) if params.command == 'scan-git' else None
                create_git_branch = getattr(params, 'git_branch', None) if params.command == 'scan-git' else None
                create_git_tag = getattr(params, 'git_tag', None) if params.command == 'scan-git' else None
                create_git_depth = getattr(params, 'git_depth', None) if params.command == 'scan-git' else None

                workbench.create_webapp_scan(
                    project_code=project_code,
                    scan_name=scan_name,
                    git_url=create_git_url,
                    git_branch=create_git_branch,
                    git_tag=create_git_tag,
                    git_depth=create_git_depth
                )
                print(f"Scan '{scan_name}' creation request sent successfully.")
                time.sleep(2)

                scan_list = workbench.get_project_scans(project_code)
                new_scan = next((s for s in scan_list if s.get('name') == scan_name), None)
                if not new_scan:
                    raise ApiError(f"Failed to retrieve details of newly created scan '{scan_name}' {search_context}.")

                scan_code = new_scan.get('code')
                scan_id_str = new_scan.get('id')
                if not scan_code or scan_id_str is None:
                    raise ValidationError(f"Newly created scan '{scan_name}' is missing required 'code' or 'id' fields.")

                try:
                    scan_id = int(scan_id_str)
                    print(f"Successfully retrieved details for new scan '{scan_name}': Code '{scan_code}', ID {scan_id_str} (Project: {project_code}).")
                    return scan_code, scan_id
                except (ValueError, TypeError):
                    raise ValidationError(f"Newly created scan '{scan_name}' has invalid ID '{scan_id_str}'")

            except ScanExistsError:
                 logger.warning(f"Scan '{scan_name}' not found initially, but creation failed because it exists. Re-resolving.")
                 return _resolve_scan(workbench, scan_name, project_name, False, params)
            except (ApiError, NetworkError, ValidationError) as e:
                 raise ApiError(f"Failed during creation or retrieval of scan '{scan_name}' {search_context}: {e}") from e
            except Exception as e:
                 logger.error(f"Unexpected error creating scan '{scan_name}' {search_context}: {e}", exc_info=True)
                 raise WorkbenchAgentError(f"Unexpected error creating scan '{scan_name}' {search_context}: {e}", details={"error": str(e)}) from e
        else:
            raise ScanNotFoundError(f"Scan '{scan_name}' not found {search_context}")

# --- Scan Compatibility Checking ---

def _ensure_scan_compatibility(params: argparse.Namespace, existing_scan_info: Dict[str, Any], scan_code: str):
    """Checks if the existing scan configuration is compatible with the current command."""
    if not existing_scan_info: return

    print(f"\nVerifying if the '{scan_code}' scan is compatible with the current operation...")

    # --- Read existing scan info ---
    existing_git_repo = existing_scan_info.get("git_repo_url", existing_scan_info.get("git_url"))
    # The API puts both branch and tag *values* in the 'git_branch' field
    existing_git_ref_value = existing_scan_info.get("git_branch")
    existing_git_ref_type = existing_scan_info.get("git_ref_type") # Directly get the type ('tag' or 'branch')

    # --- Read current command info ---
    current_command = params.command
    current_uses_git = current_command == 'scan-git'
    current_git_url = getattr(params, 'git_url', None)
    current_git_branch = getattr(params, 'git_branch', None)
    current_git_tag = getattr(params, 'git_tag', None)
    # Determine requested type and value based on flags
    current_git_ref_type = "tag" if current_git_tag else ("branch" if current_git_branch else None)
    current_git_ref_value = current_git_tag if current_git_tag else current_git_branch

    error_message = None

    # --- Compatibility Checks ---
    if current_command == 'scan':
        if existing_git_repo:
            error_message = f"Scan '{scan_code}' was created for Git scanning (Repo: {existing_git_repo}) and cannot be reused for code upload via --path."
    elif current_command == 'scan-git':
        if not existing_git_repo:
             error_message = f"Scan '{scan_code}' was created for code upload (using --path) and cannot be reused for Git scanning."
        elif existing_git_repo != current_git_url:
            error_message = (f"Scan '{scan_code}' already exists but is configured for a different Git repository "
                             f"(Existing: '{existing_git_repo}', Requested: '{current_git_url}'). "
                             f"Please use a different --scan-name to create a new scan.")
        # --- Comparison using corrected existing_git_ref_type ---
        elif current_git_ref_type and existing_git_ref_type and existing_git_ref_type.lower() != current_git_ref_type.lower(): # Compare ignoring case
             error_message = (f"Scan '{scan_code}' exists with ref type '{existing_git_ref_type}', but current command specified ref type '{current_git_ref_type}'. "
                              f"Please use a different --scan-name or use a matching ref type.")
        # --- Comparison using corrected existing_git_ref_value ---
        elif existing_git_ref_value != current_git_ref_value:
             error_message = (f"Scan '{scan_code}' already exists for {existing_git_ref_type or 'ref'} '{existing_git_ref_value}', "
                              f"but current command specified {current_git_ref_type or 'ref'} '{current_git_ref_value}'. "
                              f"Please use a different --scan-name or use the matching ref.")
    elif current_command == 'import-da':
        # DA import doesn't care about the original scan type.
        pass

    # --- Error Handling ---
    if error_message:
        print(f"\nError: Incompatible scan usage detected.")
        logger.error(f"Compatibility check failed for scan '{scan_code}': {error_message}")
        raise CompatibilityError(f"Incompatible usage for existing scan '{scan_code}': {error_message}")
    else:
        print("Compatibility check passed! Proceeding...")
        # Log reuse notes
        if current_uses_git and existing_git_repo:
             ref_display = f"{existing_git_ref_type or 'ref'} '{existing_git_ref_value}'" # Use corrected values
             logger.debug(f"Reusing existing scan '{scan_code}' configured for Git repository '{existing_git_repo}' ({ref_display}).")
        elif current_command == 'scan' and not existing_git_repo:
             logger.debug(f"Reusing existing scan '{scan_code}' configured for code upload.")
        elif current_command == 'import-da':
             logger.debug(f"Reusing existing scan '{scan_code}' for DA import.")

# --- Standard Scan Flow ---
def _execute_standard_scan_flow(workbench: 'Workbench', params: argparse.Namespace, project_code: str, scan_code: str, scan_id: int):
    """
    Executes the standard workflow after initial scan setup:
    Run KB Scan -> Wait -> Optional DA -> Wait -> Summary -> Optional Results Display/Save.
    """
    da_completed = False
    scan_completed = False

    resolved_specific_code_for_reuse = None
    api_reuse_type = None

    if params.id_reuse:
        user_provided_name_for_reuse = params.id_reuse_source
        user_reuse_type = params.id_reuse_type

        if user_reuse_type == "project":
            if not user_provided_name_for_reuse:
                 raise ConfigurationError("Missing project name in --id-reuse-source for ID reuse type 'project'.")
            print(f"Resolving project code for ID reuse source project: '{user_provided_name_for_reuse}'...")
            try:
                resolved_specific_code_for_reuse = _resolve_project(workbench, user_provided_name_for_reuse, create_if_missing=False)
                print(f"Found project code for reuse: '{resolved_specific_code_for_reuse}'")
                api_reuse_type = "specific_project"
            except ProjectNotFoundError:
                 raise ValidationError(f"The project specified in --id-reuse-source ('{user_provided_name_for_reuse}') was not found.")
            except (ApiError, NetworkError) as e:
                raise ApiError(f"Error looking up project code for reuse: {e}") from e
            except Exception as e:
                raise WorkbenchAgentError(f"Unexpected error looking up project code for reuse: {e}", details={"error": str(e)}) from e

        elif user_reuse_type == "scan":
            if not user_provided_name_for_reuse:
                 raise ConfigurationError("Missing scan name in --id-reuse-source for ID reuse type 'scan'.")
            
            try:
                # Step 1: Try to find the reuse source scan within the CURRENT project first
                logger.debug(f"Attempting to find reuse source scan '{user_provided_name_for_reuse}' within current project '{params.project_name}' ({project_code})...")
                resolved_specific_code_for_reuse, _ = _resolve_scan(
                    workbench,
                    user_provided_name_for_reuse,
                    project_name=params.project_name, # Use current project name
                    create_if_missing=False,
                    params=params # Pass params for logging context if needed
                )
                logger.info(f"Found reuse source scan '{user_provided_name_for_reuse}' with code '{resolved_specific_code_for_reuse}' within the current project.")
                api_reuse_type = "specific_scan" # API expects this value

            except (ScanNotFoundError, ValidationError) as e: # Catch if not found in current project
                # Step 2: If not found in the current project, try a global search.
                logger.warning(f"Reuse source scan '{user_provided_name_for_reuse}' not found within current project '{params.project_name}'. Attempting global search...")
                try:
                    resolved_specific_code_for_reuse, _ = _resolve_scan(
                        workbench,
                        user_provided_name_for_reuse,
                        project_name=None, # Perform global search; no project name provided.
                        create_if_missing=False,
                        params=params
                    )
                    logger.info(f"Found reuse source scan '{user_provided_name_for_reuse}' with code '{resolved_specific_code_for_reuse}' globally.")
                    api_reuse_type = "specific_scan" # API expects this value
                except (ScanNotFoundError, ValidationError, ApiError) as global_e:
                    # If global search also fails (not found or ambiguous globally), raise an error.
                    err_msg = (f"Error looking up scan code '{user_provided_name_for_reuse}' for reuse: "
                               f"Not found in project '{params.project_name}' and global search failed: {global_e}")
                    logger.error(err_msg)
                    # Raise ValidationError as it's an input/setup issue
                    raise ValidationError(err_msg) from global_e
            except (ApiError, NetworkError) as e:
                 # Catch other potential errors during the initial local lookup
                 raise ApiError(f"Error looking up scan code for reuse within project: {e}") from e
            except Exception as e:
                 raise WorkbenchAgentError(f"Unexpected error looking up scan code for reuse: {e}", details={"error": str(e)}) from e

    print("\nStarting KB Scan process...")
    try:
        workbench.assert_process_can_start("SCAN", scan_code)
        workbench.run_scan(
            scan_code,
            params.limit,
            params.sensitivity,
            params.autoid_file_licenses,
            params.autoid_file_copyrights,
            params.autoid_pending_ids,
            params.delta_scan,
            params.id_reuse,
            api_reuse_type,
            resolved_specific_code_for_reuse
        )
        print("KB Scan initiated.")
    except (CompatibilityError, ApiError, NetworkError, ScanNotFoundError, ValueError) as e:
        raise WorkbenchAgentError(f"Unexpected error starting KB Scan: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error starting KB scan for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchAgentError(f"Unexpected error starting KB scan: {e}", details={"error": str(e)}) from e

    try:
        workbench.wait_for_scan_to_finish(
            "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
        )
        scan_completed = True
        print("KB Scan process complete.")
    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        raise
    except Exception as e:
        logger.error(f"Unexpected error waiting for KB scan '{scan_code}': {e}", exc_info=True)
        raise WorkbenchAgentError(f"Unexpected error waiting for KB scan: {e}", details={"error": str(e)}) from e

    if scan_completed and params.run_dependency_analysis:
        print("\nStarting optional Dependency Analysis...")
        try:
            workbench.assert_process_can_start("DEPENDENCY_ANALYSIS", scan_code)
            workbench.start_dependency_analysis(scan_code, import_only=False)
            workbench.wait_for_scan_to_finish(
                "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time,
            )
            da_completed = True
            print("Dependency Analysis complete.")
        except CompatibilityError as e:
             logger.warning(f"Could not start Dependency Analysis for scan '{scan_code}': {e.message}")
             print(f"\nWarning: Could not start Dependency Analysis: {e.message}")
        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during dependency analysis for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during dependency analysis: {e}", details={"error": str(e)}) from e

    # --- Print Summary and Handle Results ---
    if scan_completed:
        _print_operation_summary(params, da_completed, project_code, scan_code)

        # Check for pending files (informational)
        try:
            pending_files = workbench.get_pending_files(scan_code)
            if pending_files:
                print(f"\nNote: {len(pending_files)} files have Pending Identification.")
            else:
                print("\nNote: No files found with Pending Identification.")
        except (ApiError, NetworkError) as e:
            logger.warning(f"Could not retrieve pending file count for scan '{scan_code}': {e}")
            print(f"\nWarning: Could not retrieve pending file count: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error retrieving pending file count for scan '{scan_code}': {e}", exc_info=True)
            print(f"\nWarning: Could not retrieve pending file count: {e}")

        # --- Fetch, Display, and Save Results using the new utility function ---
        _fetch_display_save_results(workbench, params, scan_code)

    elif not scan_completed:
        print("\nKB Scan did not complete successfully. Skipping results display.")

# --- Scan Flow and Result Processing ---
def format_duration(duration_seconds: Optional[Union[int, float]]) -> str:
    """Formats a duration in seconds into a 'X minutes, Y seconds' string."""
    if duration_seconds is None:
        return "N/A"
    try:
        duration_seconds = round(float(duration_seconds)) # Ensure float then round
    except (ValueError, TypeError):
        return "Invalid Duration" # Handle non-numeric input

    minutes = int(duration_seconds // 60)
    seconds = int(duration_seconds % 60)

    if minutes > 0 and seconds > 0:
        return f"{minutes} minutes, {seconds} seconds"
    elif minutes > 0:
        return f"{minutes} minutes"
    elif seconds == 1:
         return f"{seconds} second" # Singular second
    else:
        return f"{seconds} seconds" # Plural seconds or zero

def _print_operation_summary(params: argparse.Namespace, da_completed: bool, project_code: str, scan_code: str):
    """Prints a standardized summary of the scan operations performed and settings used."""
    print(f"\n--- Operation Summary for Scan '{scan_code}' (Project '{project_code}') ---")

    print("Workbench Agent Operation Details:")
    if params.command == 'scan':
        print(f"  - Method: Standard Upload (using --path)")
        print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
        print(f"  - Recursive Archive Extraction: {getattr(params, 'recursively_extract_archives', 'N/A')}")
        print(f"  - JAR File Extraction: {getattr(params, 'jar_file_extraction', 'N/A')}")
    elif params.command == 'scan-git':
        print(f"  - Method: Git Scan")
        print(f"  - Git Repository URL: {getattr(params, 'git_url', 'N/A')}")
        if getattr(params, 'git_tag', None):
            print(f"  - Git Tag: {params.git_tag}")
        elif getattr(params, 'git_branch', None):
            print(f"  - Git Branch: {params.git_branch}")
        else:
             print(f"  - Git Branch/Tag: Not Specified")
        if getattr(params, 'git_depth', None) is not None:
             print(f"  - Git Clone Depth: {params.git_depth}")
    elif params.command == 'import-da':
        print(f"  - Method: Dependency Analysis Import")
        print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
    else:
        print(f"  - Method: Unknown ({params.command})")

    if params.command in ['scan', 'scan-git']:
        print("\nKB Scan Settings:")
        print(f"  - Limit: {getattr(params, 'limit', 'N/A')}")
        print(f"  - Sensitivity: {getattr(params, 'sensitivity', 'N/A')}")
        print(f"  - Auto-ID File Licenses: {'Yes' if getattr(params, 'autoid_file_licenses', False) else 'No'}")
        print(f"  - Auto-ID File Copyrights: {'Yes' if getattr(params, 'autoid_file_copyrights', False) else 'No'}")
        print(f"  - Auto-ID Pending IDs: {'Yes' if getattr(params, 'autoid_pending_ids', False) else 'No'}")
        print(f"  - Delta Scan: {'Yes' if getattr(params, 'delta_scan', False) else 'No'}")
        print(f"  - Identification Reuse: {'Yes' if getattr(params, 'id_reuse', False) else 'No'}")
        if getattr(params, 'id_reuse', False):
            print(f"    - Reuse Type: {getattr(params, 'id_reuse_type', 'N/A')}")
            if getattr(params, 'id_reuse_type', '') in {"project", "scan"}:
                 print(f"    - Reuse Source Name: {getattr(params, 'id_reuse_source', 'N/A')}")

    print("\nAnalysis Performed:")
    kb_scan_performed = params.command in ['scan', 'scan-git']
    print(f"  - Signature (KB) Scan: {'Yes' if kb_scan_performed else 'No'}")
    print(f"  - Dependency Analysis: {'Yes' if da_completed else ('Imported' if params.command == 'import-da' else 'No')}")

    print("------------------------------------")

# --- Fetching and Displaying Results ---

def _fetch_results(workbench: 'Workbench', params: argparse.Namespace, scan_code: str) -> Dict[str, Any]:
    """
    Fetches requested scan results based on --show-* flags.
    
    Args:
        workbench: The Workbench API client instance
        params: Command-line parameters
        scan_code: Scan code to fetch results for
        
    Returns:
        Dict[str, Any]: Dictionary containing all collected results
    """
    # Get flags from parameters
    should_fetch_licenses = getattr(params, 'show_licenses', False)
    should_fetch_components = getattr(params, 'show_components', False)
    should_fetch_dependencies = getattr(params, 'show_dependencies', False)
    should_fetch_metrics = getattr(params, 'show_scan_metrics', False)
    should_fetch_policy = getattr(params, 'show_policy_warnings', False)
    should_fetch_vulnerabilities = getattr(params, 'show_vulnerabilities', False)
    
    # Check if anything should be fetched
    if not (should_fetch_licenses or should_fetch_components or should_fetch_dependencies or 
            should_fetch_metrics or should_fetch_policy or should_fetch_vulnerabilities):
        print("\n=== No Results Requested ===")
        print("No results were requested, so nothing to show.")
        print("Add (--show-licenses, --show-components, --show-dependencies, --show-scan-metrics, --show-policy-warnings, --show-vulnerabilities) to see results.")
        return {}

    print("\n=== Fetching Requested Results ===")
    collected_results = {}
    
    # --- Fetch DA Results ---
    if should_fetch_licenses or should_fetch_dependencies:
        try:
            print(f"\nFetching Dependency Analysis results for '{scan_code}'...")
            da_results_data = workbench.get_dependency_analysis_results(scan_code)
            if da_results_data:
                print(f"Successfully fetched {len(da_results_data)} DA entries.")
                collected_results['dependency_analysis'] = da_results_data
            else:
                # API method handles "not run" or empty cases
                print("No Dependency Analysis data found or returned.")
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch Dependency Analysis results: {e}")
            logger.warning(f"Failed to fetch DA results for {scan_code}", exc_info=False)
        except Exception as e:  # Catch unexpected errors
            print(f"Warning: Unexpected error fetching Dependency Analysis results: {e}")
            logger.warning(f"Unexpected error fetching DA results for {scan_code}", exc_info=True)

    # --- Fetch Identified Licenses ---
    if should_fetch_licenses:
        try:
            print(f"\nFetching KB Identified Licenses for '{scan_code}'...")
            kb_licenses_raw = workbench.get_scan_identified_licenses(scan_code)
            kb_licenses_data = sorted(kb_licenses_raw, key=lambda x: x.get('identifier', '').lower())
            if kb_licenses_data:
                print(f"Successfully fetched {len(kb_licenses_data)} unique KB licenses.")
                collected_results['kb_licenses'] = kb_licenses_data
            else:
                print("No KB Identified Licenses found.")
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch KB Identified Licenses: {e}")
            logger.warning(f"Failed to fetch KB licenses for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching KB Identified Licenses: {e}")
            logger.warning(f"Unexpected error fetching KB licenses for {scan_code}", exc_info=True)

    # --- Fetch Identified Components ---
    if should_fetch_components:
        try:
            print(f"\nFetching KB Identified Scan Components for '{scan_code}'...")
            kb_components_raw = workbench.get_scan_identified_components(scan_code)
            kb_components_data = sorted(kb_components_raw, key=lambda x: (x.get('name', '').lower(), x.get('version', '')))
            if kb_components_data:
                print(f"Successfully fetched {len(kb_components_data)} unique KB scan components.")
                collected_results['kb_components'] = kb_components_data
            else:
                print("No KB Identified Scan Components found.")
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch KB Identified Scan Components: {e}")
            logger.warning(f"Failed to fetch KB components for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching KB Identified Scan Components: {e}")
            logger.warning(f"Unexpected error fetching KB components for {scan_code}", exc_info=True)

    # --- Fetch Scan File Metrics ---
    if should_fetch_metrics:
        try:
            print(f"\nFetching Scan File Metrics for '{scan_code}'...")
            scan_metrics_data = workbench.get_scan_folder_metrics(scan_code)
            if scan_metrics_data:
                print("Successfully fetched scan file metrics.")
                collected_results['scan_metrics'] = scan_metrics_data
            else:
                # Should not happen if API method raises error on failure/empty
                print("No scan file metrics data found or returned.")
        except (ApiError, NetworkError, ScanNotFoundError) as e:
            print(f"Warning: Could not fetch Scan File Metrics: {e}")
            logger.warning(f"Failed to fetch scan metrics for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching Scan File Metrics: {e}")
            logger.warning(f"Unexpected error fetching scan metrics for {scan_code}", exc_info=True)

    # --- Fetch Policy Warnings ---
    if should_fetch_policy:
        try:
            print(f"\nFetching Scan Policy Warnings Counter for '{scan_code}'...")
            # Use the counter method for summary display
            policy_warnings_data = workbench.scans_get_policy_warnings_counter(scan_code)
            print("Successfully fetched policy warnings counter.")
            collected_results['policy_warnings'] = policy_warnings_data
        except (ApiError, NetworkError) as e:
            print(f"Warning: Could not fetch Scan Policy Warnings: {e}")
            logger.warning(f"Failed to fetch policy warnings for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching Scan Policy Warnings: {e}")
            logger.warning(f"Unexpected error fetching policy warnings for {scan_code}", exc_info=True)

    # --- Fetch Vulnerabilities ---
    if should_fetch_vulnerabilities:
        try:
            print(f"\nFetching Vulnerabilities for '{scan_code}'...")
            vulnerabilities_data = workbench.list_vulnerabilities(scan_code)
            if vulnerabilities_data:
                print(f"Successfully fetched {len(vulnerabilities_data)} vulnerability entries.")
                collected_results['vulnerabilities'] = vulnerabilities_data
            else:
                print("No Vulnerabilities found or returned.")
        except (ApiError, NetworkError, ScanNotFoundError) as e:
            print(f"Warning: Could not fetch Vulnerabilities: {e}")
            logger.warning(f"Failed to fetch vulnerabilities for {scan_code}", exc_info=False)
        except Exception as e:
            print(f"Warning: Unexpected error fetching Vulnerabilities: {e}")
            logger.warning(f"Unexpected error fetching vulnerabilities for {scan_code}", exc_info=True)
            
    return collected_results

def _display_results(collected_results: Dict[str, Any], params: argparse.Namespace) -> bool:
    """
    Displays scan results based on the collected data and user preferences.
    
    Args:
        collected_results: Dictionary containing collected results
        params: Command-line parameters with display preferences
        
    Returns:
        bool: True if any data was displayed, False otherwise
    """
    # Get flags from parameters
    should_fetch_licenses = getattr(params, 'show_licenses', False)
    should_fetch_components = getattr(params, 'show_components', False)
    should_fetch_dependencies = getattr(params, 'show_dependencies', False)
    should_fetch_metrics = getattr(params, 'show_scan_metrics', False)
    should_fetch_policy = getattr(params, 'show_policy_warnings', False)
    should_fetch_vulnerabilities = getattr(params, 'show_vulnerabilities', False)
    
    # Get data from collected results
    da_results_data = collected_results.get('dependency_analysis')
    kb_licenses_data = collected_results.get('kb_licenses')
    kb_components_data = collected_results.get('kb_components')
    scan_metrics_data = collected_results.get('scan_metrics')
    policy_warnings_data = collected_results.get('policy_warnings')
    vulnerabilities_data = collected_results.get('vulnerabilities')
    
    print("\n--- Results Summary ---")
    displayed_something = False

    # Display Scan Metrics
    if should_fetch_metrics:
        print("\n=== Scan File Metrics ===")
        displayed_something = True
        if scan_metrics_data:
            total = scan_metrics_data.get('total', 'N/A')
            pending = scan_metrics_data.get('pending_identification', 'N/A')
            identified = scan_metrics_data.get('identified_files', 'N/A')
            no_match = scan_metrics_data.get('without_matches', 'N/A')
            print(f"  - Total Files Scanned: {total}")
            print(f"  - Files Pending Identification: {pending}")
            print(f"  - Files Identified: {identified}")
            print(f"  - Files Without Matches: {no_match}")
            print("-" * 25)
        else:
            print("Scan metrics data could not be fetched or was empty.")

    # Display Licenses
    if should_fetch_licenses:
        print("\n=== Identified Licenses ===")
        displayed_something = True
        kb_licenses_found = bool(kb_licenses_data)
        da_licenses_found = False

        if kb_licenses_found:
            print("Unique Licenses in Identified Components):")
            for lic in kb_licenses_data:
                identifier = lic.get('identifier', 'N/A')
                name = lic.get('name', 'N/A')
                print(f"  - {identifier}:{name}")
            print("-" * 25)

        if da_results_data:
            da_lic_names = sorted(list(set(
                comp.get('license_identifier', 'N/A') for comp in da_results_data if comp.get('license_identifier')
            )))
            # Check if any valid licenses were found in DA data
            if da_lic_names and any(lic != 'N/A' for lic in da_lic_names):
                print("Unique Licenses in Dependencies:")
                da_licenses_found = True
                for lic_name in da_lic_names:
                    if lic_name and lic_name != 'N/A':
                        print(f"  - {lic_name}")
                print("-" * 25)

        if not kb_licenses_found and not da_licenses_found:
            print("No Licenses to report.")

    # Display KB Components
    if should_fetch_components:
        print("\n=== Identified Components ===")
        displayed_something = True
        if kb_components_data:
            print("From Signature Scanning:")
            for comp in kb_components_data:
                print(f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')}")
            print("-" * 25)
        else:
            print("No KB Scan Components found to report.")

    # Display Dependencies
    if should_fetch_dependencies:
        print("\n=== Dependency Analysis Results ===")
        displayed_something = True
        if da_results_data:
            print("Component, Version, Scope, and License of Dependencies:")
            da_results_data.sort(key=lambda x: (x.get('name', '').lower(), x.get('version', '')))
            for comp in da_results_data:
                scopes_display = "N/A"
                scopes_str = comp.get("projects_and_scopes")
                if scopes_str:
                    try:
                        scopes_data = json.loads(scopes_str)
                        scopes_list = sorted(list(set(
                            p_info.get("scope") for p_info in scopes_data.values() if isinstance(p_info, dict) and p_info.get("scope")
                        )))
                        if scopes_list: scopes_display = ", ".join(scopes_list)
                    except (json.JSONDecodeError, AttributeError, TypeError) as scope_err:
                        logger.debug(f"Could not parse scopes for DA component {comp.get('name')}: {scope_err}")
                        pass
                print(f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')} "
                      f"(Scope: {scopes_display}, License: {comp.get('license_identifier', 'N/A')})")
            print("-" * 25)
        else:
            print("No Components found through Dependency Analysis.")

    # Display Policy Warnings
    if should_fetch_policy:
        print("\n=== Policy Warnings Summary ===")
        displayed_something = True
        if policy_warnings_data is not None:
            # Check if we have real data with non-zero values
            total_warnings = int(policy_warnings_data.get("policy_warnings_total", 0))
            files_with_warnings = int(policy_warnings_data.get("identified_files_with_warnings", 0))
            deps_with_warnings = int(policy_warnings_data.get("dependencies_with_warnings", 0))
            
            if total_warnings > 0:
                print(f"There are {total_warnings} policy warnings. "
                      f"Warnings in Identified Files: {files_with_warnings}. "
                      f"Warnings in Dependencies: {deps_with_warnings}.")
            else:
                print("No policy warnings found.")
        else:
            print("Policy warnings counter data could not be fetched or was empty.")
        print("-" * 25)

    # Display Vulnerability Summary
    if should_fetch_vulnerabilities:
        print("\n=== Vulnerability Summary ===")
        displayed_something = True
        if vulnerabilities_data:
            num_cves = len(vulnerabilities_data)
            unique_components = set()
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

            for vuln in vulnerabilities_data:
                comp_name = vuln.get("component_name", "Unknown")
                comp_version = vuln.get("component_version", "Unknown")
                unique_components.add(f"{comp_name}:{comp_version}")
                severity = vuln.get("severity", "UNKNOWN").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            num_unique_components = len(unique_components)
            print(f"There are {num_cves} vulnerabilities affecting {num_unique_components} components.")
            print(f"By CVSS Score, "
                  f"{severity_counts['CRITICAL']} are Critical, "
                  f"{severity_counts['HIGH']} are High, "
                  f"{severity_counts['MEDIUM']} are Medium, and "
                  f"{severity_counts['LOW']} are Low.")

            if severity_counts['UNKNOWN'] > 0: print(f"  - Unknown:  {severity_counts['UNKNOWN']}")

        print("\n=== Top Vulnerable Components ===")
        if vulnerabilities_data:
            components_vulns = {}
            # Group vulnerabilities by component:version
            for vuln in vulnerabilities_data:
                comp_name = vuln.get("component_name", "UnknownComponent")
                comp_version = vuln.get("component_version", "UnknownVersion")
                comp_key = f"{comp_name}:{comp_version}"
                if comp_key not in components_vulns:
                    components_vulns[comp_key] = []
                components_vulns[comp_key].append(vuln)

            # Sort components by the number of vulnerabilities (descending)
            sorted_components = sorted(components_vulns.items(), key=lambda item: len(item[1]), reverse=True)

            # Define severity order for sorting vulnerabilities within each component
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

            for comp_key, vulns_list in sorted_components:
                print(f"\n{comp_key} - {len(vulns_list)} vulnerabilities")

                # Sort vulnerabilities within this component by severity
                sorted_vulns_list = sorted(
                    vulns_list,
                    key=lambda v: severity_order.get(v.get("severity", "UNKNOWN").upper(), 0),
                    reverse=True
                )

                # Display top 5 vulnerabilities for each component
                for i, vuln in enumerate(sorted_vulns_list[:5]):
                    severity = vuln.get("severity", "UNKNOWN").upper()
                    cve = vuln.get("cve", "NO_CVE_ID")
                    print(f"  - [{severity}] {cve}")
                if len(sorted_vulns_list) > 5:
                    print(f"  ... and {len(sorted_vulns_list) - 5} more.")
        else:
            print("Vulnerability data could not be fetched or was empty.")
        print("-" * 25)

    if not displayed_something:
        print("No results were successfully fetched or displayed for the specified flags.")
    print("------------------------------------")
    
    return displayed_something

def _fetch_display_save_results(workbench: 'Workbench', params: argparse.Namespace, scan_code: str):
    """
    Fetches requested scan results, displays them, and optionally saves them to a file.
    This function orchestrates the fetch, display, and save operations.
    
    Args:
        workbench: The Workbench API client instance
        params: Command-line parameters
        scan_code: Scan code to fetch results for
    """
    # 1. Fetch the results
    collected_results = _fetch_results(workbench, params, scan_code)
    
    # 2. Display the results
    if collected_results:
        _display_results(collected_results, params)
    
    # 3. Save the results if requested
    save_path = getattr(params, 'path_result', None)
    if save_path:
        if collected_results:
            print(f"\nSaving collected results to '{save_path}'...")
            _save_results_to_file(save_path, collected_results, scan_code)
        else:
            print("\nNo results were successfully collected, skipping save.")

# --- Scan Result Saving ---
def _save_results_to_file(filepath: str, results: Dict, scan_code: str):
    """Helper to save collected results dictionary to a JSON file."""
    output_dir = os.path.dirname(filepath) or "."
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Saved results to: {filepath}")
        logger.info(f"Saved results for scan '{scan_code}' to {filepath}")
    except (IOError, OSError) as e:
         logger.warning(f"Failed to save results to {filepath}: {e}")
         print(f"\nWarning: Failed to save results to {filepath}: {e}")
    except Exception as e:
         logger.warning(f"Unexpected error saving results to {filepath}: {e}", exc_info=True)
         print(f"\nWarning: Unexpected error saving results: {e}")

# --- Report Saving ---
def _save_report_content(
    response_or_content: Union[requests.Response, str, bytes, dict, list],
    output_dir: str,
    report_scope: str,
    name_component: str,
    report_type: str
) -> None:
    """
    Saves report content (from response object or direct content) to a file.
    (Docstring omitted for brevity in this example, but should be kept)
    """
    if not output_dir:
        raise ValidationError("Output directory is not specified for saving report.")
    if not name_component:
        raise ValidationError("Name component (scan/project name) is not specified for saving report.")
    if not report_type:
        raise ValidationError("Report type is not specified for saving report.")

    filename = ""
    content_to_write: Union[str, bytes] = b""
    write_mode = 'wb'

    if isinstance(response_or_content, requests.Response):
        response = response_or_content

        # --- Always generate filename based on desired format ---
        safe_name = re.sub(r'[^\w\-]+', '_', name_component) # Allow letters, numbers, underscore, hyphen
        safe_scope = report_scope # Scope is already validated ('scan' or 'project')
        safe_type = re.sub(r'[^\w\-]+', '_', report_type)
        extension_map = {
            "xlsx": "xlsx", "spdx": "rdf", "spdx_lite": "xlsx",
            "cyclone_dx": "json", "html": "html", "dynamic_top_matched_components": "html",
            "string_match": "xlsx", "basic": "txt"
        }
        ext = extension_map.get(report_type.lower(), "txt") # Default to .txt if unknown
        filename = f"{safe_scope}-{safe_name}-{safe_type}.{ext}"
        logger.debug(f"Generated filename: {filename}")

        try:
            content_to_write = response.content
        except Exception as e:
            raise FileSystemError(f"Failed to read content from response object: {e}")

        content_type = response.headers.get('content-type', '').lower()
        if 'text' in content_type or 'json' in content_type or 'html' in content_type:
            write_mode = 'w'
            try:
                content_to_write = content_to_write.decode(response.encoding or 'utf-8', errors='replace')
            except Exception:
                 logger.warning(f"Could not decode response content as text, writing as binary. Content-Type: {content_type}")
                 write_mode = 'wb'
        else:
            write_mode = 'wb'

    elif isinstance(response_or_content, (dict, list)):
        # Handle direct JSON data (e.g., collected results)
        safe_name = re.sub(r'[^\w\-]+', '_', name_component)
        safe_scope = report_scope
        safe_type = re.sub(r'[^\w\-]+', '_', report_type) # Use report_type if available, else generic
        filename = f"{safe_scope}-{safe_name}-{safe_type}.json"
        try:
            content_to_write = json.dumps(response_or_content, indent=2)
            write_mode = 'w'
        except TypeError as e:
            raise ValidationError(f"Failed to serialize provided dictionary/list to JSON: {e}")
    elif isinstance(response_or_content, str):
        # Handle direct string content
        safe_name = re.sub(r'[^\w\-]+', '_', name_component)
        safe_scope = report_scope
        safe_type = re.sub(r'[^\w\-]+', '_', report_type)
        filename = f"{safe_scope}-{safe_name}-{safe_type}.txt"
        content_to_write = response_or_content
        write_mode = 'w'
    elif isinstance(response_or_content, bytes):
        # Handle direct bytes content
        safe_name = re.sub(r'[^\w\-]+', '_', name_component)
        safe_scope = report_scope
        safe_type = re.sub(r'[^\w\-]+', '_', report_type)
        filename = f"{safe_scope}-{safe_name}-{safe_type}.bin" # Generic binary extension
        content_to_write = response_or_content
        write_mode = 'wb'
    else:
        raise ValidationError(f"Unsupported content type for saving: {type(response_or_content)}")

    filepath = os.path.join(output_dir, filename)

    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        logger.error(f"Failed to create output directory '{output_dir}': {e}", exc_info=True)
        raise FileSystemError(f"Could not create output directory '{output_dir}': {e}") from e

    try:
        encoding_arg = {'encoding': 'utf-8'} if write_mode == 'w' else {}
        with open(filepath, write_mode, **encoding_arg) as f:
            f.write(content_to_write)
        print(f"Saved report to: {filepath}")
        logger.info(f"Successfully saved report to {filepath}")
    except IOError as e:
        logger.error(f"Failed to write report to {filepath}: {e}", exc_info=True)
        raise FileSystemError(f"Failed to write report to '{filepath}': {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error writing report to {filepath}: {e}", exc_info=True)
        raise FileSystemError(f"Unexpected error writing report to '{filepath}': {e}") from e
