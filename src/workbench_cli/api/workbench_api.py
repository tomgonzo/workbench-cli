from typing import Dict, List, Optional, Union, Any, Generator, Tuple
import logging
from .workbench_api_helpers import WorkbenchAPIHelpers
from .workbench_api_upload import WorkbenchAPIUpload
from .helpers.project_scan_resolvers import ResolveWorkbenchProjectScan
from ..exceptions import (
    WorkbenchCLIError,
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
import json
import requests
import os
import base64
import tempfile
import shutil
import time

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-cli")

class WorkbenchAPI(WorkbenchAPIUpload, ResolveWorkbenchProjectScan):
    """
    Workbench API client class for interacting with the FossID Workbench API.
    Extends WorkbenchAPIHelpers to provide actual API operations.
    """
    # --- Report Types ---
    ASYNC_REPORT_TYPES = {"xlsx", "spdx", "spdx_lite", "cyclone_dx", "basic"}
    PROJECT_REPORT_TYPES = {"xlsx", "spdx", "spdx_lite", "cyclone_dx"}
    SCAN_REPORT_TYPES = {"html", "dynamic_top_matched_components", "xlsx", "spdx", "spdx_lite", "cyclone_dx", "string_match"}

    def __init__(self, api_url: str, api_user: str, api_token: str):
        """
        Initialize the Workbench API client.

        Args:
            api_url: URL to the API endpoint (with or without api.php suffix)
            api_user: API username 
            api_token: API token/key
        """
        super().__init__(api_url, api_user, api_token)

# Project and Scan Resolving
    def list_projects(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all projects.

        Returns:
            List[Dict[str, Any]]: List of project data

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Listing all projects...")
        payload = {
            "group": "projects",
            "action": "list_projects",
            "data": {}
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully listed {len(data)} projects.")
                return data
            else:
                logger.warning(f"API returned success for list_projects but 'data' was not a list: {type(data)}")
                return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list projects: {error_msg}", details=response)

    def list_scans(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans.

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Listing all scans...")
        payload = {
            "group": "scans",
            "action": "list_scans",
            "data": {}
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            # API returns a dict {id: {details}}, convert to list of dicts including the code
            if isinstance(data, dict):
                scan_list = []
                for scan_id, scan_details in data.items():
                    if isinstance(scan_details, dict):
                        # Add the 'id' from the key and potentially 'code' if present
                        try: # Handle potential non-integer scan_id keys if API is weird
                            scan_details['id'] = int(scan_id)
                        except ValueError:
                            logger.warning(f"Non-integer scan ID key found in list_scans response: {scan_id}")
                            scan_details['id'] = scan_id # Keep original key if not int

                        # 'code' should be in scan_details based on previous API info
                        if 'code' not in scan_details:
                            logger.warning(f"Scan details for ID {scan_id} missing 'code' field: {scan_details}")
                        scan_list.append(scan_details)
                    else:
                        logger.warning(f"Unexpected format for scan details with ID {scan_id}: {type(scan_details)}")
                logger.debug(f"Successfully listed {len(scan_list)} scans.")
                return scan_list
            elif isinstance(data, list) and not data: # Handle API returning empty list for no scans
                logger.debug("Successfully listed 0 scans (API returned empty list).")
                return []
            else:
                logger.warning(f"API returned success for list_scans but 'data' was not a dict or empty list: {type(data)}")
                return [] # Return empty list on unexpected format
        elif response.get("status") == "1": # Status 1 but no data key
            logger.warning(f"API returned success for list_scans but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list scans: {error_msg}", details=response)

    def get_project_scans(self, project_code: str) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans within a specific project.

        Args:
            project_code: Code of the project to get scans for

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            ProjectNotFoundError: If the project doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug(f"Listing scans for the '{project_code}' project...")
        payload = {
            "group": "projects",
            "action": "get_all_scans",
            "data": {
                "project_code": project_code
            }
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully listed {len(data)} scans for project '{project_code}'.")
                return data
            else:
                logger.warning(f"API returned success for get_all_scans but 'data' was not a list: {type(data)}")
                return []
        elif response.get("status") == "1":
            logger.warning(f"API returned success for get_all_scans but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            # Treat project not found as empty list of scans
            if "Project code does not exist" in error_msg or "row_not_found" in error_msg:
                logger.warning(f"Project '{project_code}' not found when trying to list its scans.")
                return []
            else:
                raise ApiError(f"Failed to list scans for project '{project_code}': {error_msg}", details=response)

    def create_project(self, project_name: str) -> str:
        """
        Create a new project in Workbench.
        
        Args:
            project_name: Name of the project to create
            
        Returns:
            The project code of the created project
            
        Raises:
            ProjectExistsError: If a project with this name already exists
            ApiError: If project creation fails
            NetworkError: If there are network issues
        """
        try:
            # First check if project exists
            projects = self.list_projects()
            for project in projects:
                if project.get("name") == project_name:
                    raise ProjectExistsError(f"Project '{project_name}' already exists")

            # Create the project
            payload = {
                "group": "projects",
                "action": "create",
                "data": {
                    "project_name": project_name,
                }
            }
            response = self._send_request(payload)
            
            if response.get("status") == "1":
                project_code = response.get("data", {}).get("project_code")
                if not project_code:
                    raise ApiError("Project created but no code returned", details=response)
                return project_code
            else:
                error_msg = response.get("error", "Unknown error")
                raise ApiError(f"Failed to create project '{project_name}': {error_msg}", details=response)
                
        except ProjectExistsError:
            raise
        except Exception as e:
            if isinstance(e, ApiError):
                raise
            raise ApiError(f"Failed to create project '{project_name}'", details={"error": str(e)})

    def create_webapp_scan(
        self,
        scan_name: str,
        project_code: str,
        git_url: Optional[str] = None,
        git_branch: Optional[str] = None,
        git_tag: Optional[str] = None,
        git_commit: Optional[str] = None,
        git_depth: Optional[int] = None
    ) -> bool:
        """
        Creates a new webapp scan inside a project, handling Git parameters as needed.
        
        Args:
            scan_name: Name for the new scan.
            project_code: Project code where the scan should be created.
            git_url: Optional URL to a Git repository for Git-based scan.
            git_branch: Optional branch name (if git_url is provided).
            git_tag: Optional tag name (if git_url is provided, alternative to branch).
            git_commit: Optional commit hash (if git_url is provided, alternative to branch or tag).
            git_depth: Optional git clone depth (if git_url is provided).
            
        Returns:
            True if the scan was successfully created, raises exception otherwise.
            
        Raises:
            ApiError: If the API call fails.
            NetworkError: If there's a network issue.
            ScanExistsError: If a scan with this code already exists.
        """
        logger.debug(f"Creating new scan '{scan_name}' in project '{project_code}'")
        
        payload_data = {
            "scan_name": scan_name,
            "project_code": project_code,
        }
        
        # --- Correct Git Parameter Handling ---
        git_ref_value = None
        git_ref_type = None
        
        if git_tag:
            git_ref_value = git_tag
            git_ref_type = "tag"
            logger.debug(f"  Including Git Tag: {git_tag}")
        elif git_branch:
            git_ref_value = git_branch
            git_ref_type = "branch"
            logger.debug(f"  Including Git Branch: {git_branch}")
        elif git_commit:
            git_ref_value = git_commit
            git_ref_type = "commit"
            logger.debug(f"  Including Git Commit: {git_commit}")
        # If neither branch, tag, or commit are provided but git_url is, API might default,
        # but our argparse setup requires one of the three for scan-git.
        
        if git_url:
            # Include Git parameters only if a Git URL is provided
            payload_data["git_repo_url"] = git_url
            logger.debug(f"  Including Git URL: {git_url}")
            if git_ref_value:
                # API uses 'git_branch' field for BOTH branch and tag values
                payload_data["git_branch"] = git_ref_value
                if git_ref_type:
                    # Explicit ref_type helps Workbench know if it's a branch or tag
                    payload_data["git_ref_type"] = git_ref_type
                    logger.debug(f"  Setting Git Ref Type to: {git_ref_type}")
                if git_depth is not None:
                    # Only include depth if a positive number is provided
                    payload_data["git_depth"] = str(git_depth)
                    logger.debug(f"  Setting Git Clone Depth to: {git_depth}")
            elif git_depth is not None:
                # If depth is provided but no ref type, we need to set a default
                if not git_ref_type:
                    logger.warning("Git depth specified, but no branch or tag provided. Setting ref type to 'branch' as a default.")
                    payload_data["git_ref_type"] = "branch"
                payload_data["git_depth"] = str(git_depth)
                logger.debug(f"  Setting Git Clone Depth to: {git_depth}")
        
        payload = {
            "group": "scans",
            "action": "create",
            "data": payload_data
        }
        
        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                logger.debug(f"Successfully created scan '{scan_name}'")
                return True
            else:
                logger.warning(f"Unexpected response when creating scan: {response}")
                # This shouldn't happen as _send_request should raise ApiError for status 0
                # But handle it just in case
                error_msg = response.get("error", "Unknown error")
                raise ApiError(f"Failed to create scan: {error_msg}", details=response)
        except ApiError as e:
            if "Scan code already exists" in str(e) or "Legacy.controller.scans.code_already_exists" in str(e):
                logger.debug(f"Scan '{scan_name}' already exists.")
                raise ScanExistsError(f"Scan '{scan_name}' already exists", details=getattr(e, 'details', None))
            raise

# Scan Ops: File Operations
    def download_content_from_git(self, scan_code: str) -> bool:
        """
        Initiates the Git clone process for a scan.
        
        Args:
            scan_code: The code of the scan to download Git content for.
            
        Returns:
            True if the Git clone was successfully initiated.
            
        Raises:
            ApiError: If the API call fails.
            NetworkError: If there's a network issue.
        """
        logger.debug(f"Initiating Git clone for scan '{scan_code}'")
        
        payload = {
            "group": "scans",
            "action": "download_content_from_git",
            "data": {"scan_code": scan_code}
        }
        
        response = self._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown error")
            raise ApiError(f"Failed to initiate download from Git: {error_msg}", details=response)
        
        logger.debug("Successfully started Git Clone.")
        return True
        
    def check_status_download_content_from_git(self, scan_code: str) -> str:
        """
        Checks the status of a Git clone operation.
        
        Args:
            scan_code: The code of the scan to check Git clone status for.
            
        Returns:
            The status of the Git clone operation ("FINISHED", "RUNNING", "FAILED", etc.).
            
        Raises:
            ApiError: If the API call fails.
            NetworkError: If there's a network issue.
        """
        logger.debug(f"Checking Git clone status for scan '{scan_code}'")
        
        payload = {
            "group": "scans",
            "action": "check_status_download_content_from_git",
            "data": {"scan_code": scan_code}
        }
        
        response = self._send_request(payload)
        return response.get("data", "UNKNOWN")
        

    def remove_uploaded_content(self, scan_code: str, filename: str) -> bool:
        """
        Removes uploaded content from a scan, particularly useful for removing files or folders
        prior to starting a scan.

        Args:
            scan_code: Code of the scan to remove content from
            filename: Name/path of the file or directory to remove (e.g., ".git/")

        Returns:
            bool: True if the operation was successful

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug(f"Removing '{filename}' from scan '{scan_code}'...")
        
        payload = {
            "group": "scans",
            "action": "remove_uploaded_content",
            "data": {
                "scan_code": scan_code,
                "filename": filename
            }
        }
        
        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                logger.debug(f"Successfully removed '{filename}' from scan '{scan_code}'.")
                return True
            else:
                error_msg = response.get("error", "Unknown error")
                
                # Check if this is the specific "file not found" error
                if error_msg == "RequestData.Base.issues_while_parsing_request":
                    data = response.get("data", [])
                    if isinstance(data, list) and len(data) > 0:
                        error_code = data[0].get("code", "")
                        if error_code == "RequestData.Traits.PathTrait.filename_is_not_valid":
                            logger.warning(f"File or directory '{filename}' does not exist in scan '{scan_code}' or could not be accessed.")
                            # Return True as this is non-fatal - the file we wanted removed doesn't exist anyway
                            return True
                
                # Handle other types of errors
                if "Scan not found" in error_msg or "row_not_found" in error_msg:
                    raise ScanNotFoundError(f"Scan '{scan_code}' not found")
                
                raise ApiError(f"Failed to remove '{filename}' from scan '{scan_code}': {error_msg}", details=response)
        except (ScanNotFoundError, ApiError, NetworkError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error removing '{filename}' from scan '{scan_code}': {e}", exc_info=True)
            raise ApiError(f"Failed to remove '{filename}' from scan '{scan_code}': Unexpected error", details={"error": str(e)})

    def extract_archives(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
    ):
        """
        Triggers archive extraction for a scan.

        Args:
            scan_code: Code of the scan to extract archives for
            recursively_extract_archives: Whether to recursively extract archives
            jar_file_extraction: Whether to extract JAR files

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug(f"Extracting Uploaded Archives for Scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "extract_archives",
            "data": {
                "scan_code": scan_code,
                # API expects boolean as string "true"/"false" or integer 1/0
                "recursively_extract_archives": str(recursively_extract_archives).lower(),
                "jar_file_extraction": str(jar_file_extraction).lower(),
            },
        }
        response = self._send_request(payload)
        if response.get("status") == "1":
            logger.debug(f"Archive Extraction operation successfully queued/completed for scan '{scan_code}'.")
            return True
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Archive extraction failed for scan '{scan_code}': {error_msg}",
                details=response
            )

# Scan Ops: Scanner Operations
    def run_scan(
        self,
        scan_code: str,
        limit: int,
        sensitivity: int,
        autoid_file_licenses: bool,
        autoid_file_copyrights: bool,
        autoid_pending_ids: bool,
        delta_scan: bool,
        id_reuse: bool,
        id_reuse_type: Optional[str] = None,
        id_reuse_source: Optional[str] = None,
        run_dependency_analysis: Optional[bool] = None,
    ):
        """
        Run a scan with the specified parameters.
        
        Args:
            scan_code: The code of the scan to run
            limit: Maximum number of results to consider
            sensitivity: Scan sensitivity level
            autoid_file_licenses: Whether to auto-identify file licenses
            autoid_file_copyrights: Whether to auto-identify file copyrights
            autoid_pending_ids: Whether to auto-identify pending IDs
            delta_scan: Whether to run a delta scan
            id_reuse: Whether to reuse identifications from other scans
            id_reuse_type: Type of identification reuse (project, scan, only_me, any)
            id_reuse_source: Source to reuse identifications from (required for project/scan types)
            run_dependency_analysis: Whether to run dependency analysis along with the scan
            
        Notes:
            For id_reuse parameters, validation should be done prior to calling this method
            using the _validate_reuse_source function from workbench_cli.utils.
            If validation fails, id_reuse should be set to False before calling this method.
            
        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            ValueError: For invalid parameter values
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "run",
            "data": {
                "scan_code": scan_code,
                "limit": limit,
                "sensitivity": sensitivity,
                "auto_identification_detect_declaration": int(autoid_file_licenses),
                "auto_identification_detect_copyright": int(autoid_file_copyrights),
                "auto_identification_resolve_pending_ids": int(autoid_pending_ids),
                "delta_only": int(delta_scan),
            }
        }

        if id_reuse:
            # Determine the value to send to the API based on the user input
            api_reuse_type_value = id_reuse_type

            if id_reuse_type == "project":
                api_reuse_type_value = "specific_project"
            elif id_reuse_type == "scan":
                api_reuse_type_value = "specific_scan"
            elif id_reuse_type == "only_me":
                api_reuse_type_value = "only_me"
            else:
                api_reuse_type_value = "any" # Default to "any"

            # Safety check: ensure specific_code is provided for project/scan reuse
            if api_reuse_type_value in ['specific_project', 'specific_scan'] and not id_reuse_source:
                logger.warning(f"ID reuse disabled because no source was provided for {id_reuse_type} reuse type.")
                # Skip adding reuse parameters
            else:
                # Add ID reuse parameters to the payload
                data = payload["data"]
                data["reuse_identification"] = "1"
                data["identification_reuse_type"] = api_reuse_type_value
                
                # Include specific_code for project/scan reuse types
                if api_reuse_type_value in ['specific_project', 'specific_scan']:
                    data["specific_code"] = id_reuse_source
        
        # Add dependency analysis parameter if requested
        if run_dependency_analysis:
            payload["data"]["run_dependency_analysis"] = "1"

        # --- Send Request ---
        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                print(f"KB Scan initiated for scan '{scan_code}'.")
                return # Return None or True on success
            else:
                error_msg = response.get("error", "Unknown error")
                if "Scan not found" in error_msg:
                    raise ScanNotFoundError(f"Scan '{scan_code}' not found")
                raise ApiError(f"Failed to run scan '{scan_code}': {error_msg}", details=response)
        except (ScanNotFoundError, ApiError):
             raise # Re-raise specific errors
        except Exception as e:
             # Catch other errors like network issues from _send_request
             logger.error(f"Unexpected error trying to run scan '{scan_code}': {e}", exc_info=True)
             raise ApiError(f"Failed to run scan '{scan_code}': {e}") from e

    def start_dependency_analysis(self, scan_code: str, import_only: bool = False):
        """
        Starts or imports dependency analysis for a scan.

        Args:
            scan_code: Code of the scan to start dependency analysis for
            import_only: Whether to only import results without running analysis

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": {
                "scan_code": scan_code,
            },
        }
        if import_only:
            payload["data"]["import_only"] = "1"
            print("DA Result Import Mode.")
            print(f"Importing DA results into Scan '{scan_code}'.")
        else:
            logger.debug(f"Starting Dependency Analysis for scan '{scan_code}'.")

        response = self._send_request(payload)
        if response.get("status") == "1":
            print(f"Dependency Analysis started for scan '{scan_code}'.")
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Dependency Analysis for scan '{scan_code}' failed to start: {error_msg}",
                details=response
            )

    def get_scan_status(self, scan_type: str, scan_code: str) -> dict:
        """
        Retrieves the status of a scan operation (SCAN or DEPENDENCY_ANALYSIS).

        Args:
            scan_type: Type of scan operation (SCAN or DEPENDENCY_ANALYSIS)
            scan_code: Code of the scan to check

        Returns:
            dict: The scan status data

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "scan_code": scan_code,
                "type": scan_type.upper(),
            },
        }
        response = self._send_request(payload)
        # _send_request handles basic API errors, check for expected data
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response format: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to retrieve {scan_type} status for scan '{scan_code}': {error_msg}",
                details=response
            )

    def get_scan_information(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves detailed information about a scan.
        
        Args:
            scan_code: Code of the scan to get information for
            
        Returns:
            Dict[str, Any]: Dictionary containing scan information
            
        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching information for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_information",
            "data": {"scan_code": scan_code}
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "row_not_found" in error_msg or "Scan not found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(f"Failed to get information for scan '{scan_code}': {error_msg}", details=response)

# Scan Ops: Results Operations
    def get_scan_folder_metrics(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves scan folder metrics (total files, pending, identified, no match).

        Args:
            scan_code: Code of the scan to get metrics for

        Returns:
            Dict[str, Any]: Dictionary containing the metrics counts.

        Raises:
            ScanNotFoundError: If the scan doesn't exist.
            ApiError: If the API call fails for other reasons.
            NetworkError: If there are network issues.
        """
        logger.debug(f"Fetching folder metrics for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_folder_metrics",
            "data": {"scan_code": scan_code}
        }
        response = self._send_request(payload)

        if response.get("status") == "1" and "data" in response and isinstance(response["data"], dict):
            logger.info(f"Successfully fetched folder metrics for scan '{scan_code}'.")
            return response["data"]
        elif response.get("status") == "1": # Status 1 but no data or wrong format
             logger.warning(f"Folder metrics API returned success but unexpected data format for scan '{scan_code}': {response.get('data')}")
             raise ApiError(f"Unexpected data format received for scan folder metrics: {response.get('data')}", details=response)
        else:
            # Handle API errors (status 0)
            error_msg = response.get("error", "Unknown API error")
            if "row_not_found" in error_msg:
                logger.warning(f"Scan '{scan_code}' not found when fetching folder metrics.")
                raise ScanNotFoundError(f"Scan '{scan_code}' not found.")
            else:
                logger.error(f"API error fetching folder metrics for scan '{scan_code}': {error_msg}")
                raise ApiError(f"Failed to get scan folder metrics: {error_msg}", details=response)
    
    def get_scan_identified_components(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Gets identified components from KB scanning.

        Args:
            scan_code: Code of the scan to get components from

        Returns:
            List[Dict[str, Any]]: List of identified components

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_components",
            "data": { "scan_code": scan_code },
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            # API returns a dict { comp_id: {details} }, convert to list
            data = response["data"]
            return list(data.values()) if isinstance(data, dict) else []
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error retrieving identified components from scan '{scan_code}': {error_msg}",
                details=response
            )

    def get_scan_identified_licenses(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Get the list of identified licenses for a scan.

        Args:
            scan_code: Code of the scan to get licenses from

        Returns:
            List[Dict[str, Any]]: List of identified licenses

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {
                "scan_code": scan_code,
                "unique": "1"
            }
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully fetched {len(data)} unique licenses.")
                return data
            else:
                logger.warning(f"API returned success for get_scan_identified_licenses but 'data' was not a list: {type(data)}")
                return []
        elif response.get("status") == "1":
            logger.warning("API returned success for get_scan_identified_licenses but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response format or status: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error getting identified licenses for scan '{scan_code}': {error_msg}",
                details=response
            )

    def get_dependency_analysis_results(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Gets dependency analysis results.

        Args:
            scan_code: Code of the scan to get results from

        Returns:
            List[Dict[str, Any]]: List of dependency analysis results

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_dependency_analysis_results",
            "data": { "scan_code": scan_code },
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            return data if isinstance(data, list) else []
        elif response.get("status") == "1": # Success but no data key
            logger.info(f"Dependency Analysis results requested for '{scan_code}', but no 'data' key in response. Assuming empty.")
            return [] # Return empty list, not an error
        else:
            # Check for specific "not run yet" error
            error_msg = response.get("error", "")
            if "Dependency analysis has not been run" in error_msg:
                logger.info(f"Dependency analysis results requested for '{scan_code}', but analysis has not been run.")
                return [] # Return empty list, not an error
            elif "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            else:
                raise ApiError(
                    f"Error getting dependency analysis results for scan '{scan_code}': {error_msg}",
                    details=response
                )

    def get_pending_files(self, scan_code: str) -> Dict[str, str]:
        """
        Retrieves pending files for a scan.
        
        Args:
            scan_code: Code of the scan to check
            
        Returns:
            Dict[str, str]: Dictionary of pending files
            
        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Fetching files with Pending IDs for scan '{scan_code}'...")
        payload = {
            "group": "scans", 
            "action": "get_pending_files", 
            "data": {"scan_code": scan_code}
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug(f"The scan {scan_code} has {len(data)} files pending ID'.")
                return data
            elif isinstance(data, list) and not data: # Handle API sometimes returning empty list?
                 logger.info(f"Pending files API returned empty list for scan '{scan_code}'.")
                 return {} # Return empty dict
            else:
                # Log unexpected format but return empty dict
                logger.warning(f"Pending files API returned unexpected data type: {type(data)}")
                return {}
        elif response.get("status") == "1": # Status 1 but no data key
             logger.info(f"Pending files API returned success but no 'data' key for scan '{scan_code}'.")
             return {}
        else:
            # On API error (status 0), log but return empty dict - let handler decide gate status
            error_msg = response.get("error", f"Unexpected response: {response}")
            logger.error(f"Failed to get pending files for scan '{scan_code}': {error_msg}")
            return {} # Return empty dict on error

    def get_policy_warnings_counter(self, scan_code: str) -> Dict[str, Any]:
        """
        Gets the count of policy warnings for a specific scan.

        Args:
            scan_code: Code of the scan to get policy warnings for

        Returns:
            Dict[str, Any]: The policy warnings counter data

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_policy_warnings_counter",
            "data": { "scan_code": scan_code },
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error getting scan policy warnings counter for '{scan_code}': {error_msg}",
                details=response
            )

    def list_vulnerabilities(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Retrieves the list of vulnerabilities associated with a scan.
        Handles pagination automatically to fetch all vulnerabilities.

        Args:
            scan_code: Code of the scan to get vulnerabilities for.

        Returns:
            List[Dict[str, Any]]: List of vulnerability details.

        Raises:
            ApiError: If there are API issues.
            ScanNotFoundError: If the scan doesn't exist.
            NetworkError: If there are network issues.
        """
        logger.debug(f"Fetching vulnerabilities for scan '{scan_code}'...")
        
        # Step 1: Get the total count of vulnerabilities
        count_payload = {
            "group": "vulnerabilities",
            "action": "list_vulnerabilities",
            "data": {
                "scan_code": scan_code,
                "count_results": 1
            }
        }
        count_response = self._send_request(count_payload)
        
        if count_response.get("status") != "1":
            error_msg = count_response.get("error", f"Unexpected response format or status: {count_response}")
            raise ApiError(f"Failed to get vulnerability count for scan '{scan_code}': {error_msg}", details=count_response)
        
        # Get the total count from the response
        total_count = 0
        if (isinstance(count_response.get("data"), dict) and 
            "count_results" in count_response["data"]):
            total_count = int(count_response["data"]["count_results"])
            
        logger.debug(f"Found {total_count} total vulnerabilities for scan '{scan_code}'")
        
        # If no vulnerabilities, return an empty list
        if total_count == 0:
            return []
            
        # Step 2: Calculate number of pages needed (default records_per_page is 100)
        records_per_page = 100
        total_pages = (total_count + records_per_page - 1) // records_per_page  # Ceiling division
        
        # Step 3: Fetch all pages and combine results
        all_vulnerabilities = []
        
        for page in range(1, total_pages + 1):
            logger.debug(f"Fetching vulnerabilities page {page}/{total_pages} for scan '{scan_code}'")
            
            page_payload = {
                "group": "vulnerabilities",
                "action": "list_vulnerabilities",
                "data": {
                    "scan_code": scan_code,
                    "page": page
                }
            }
            page_response = self._send_request(page_payload)
            
            if page_response.get("status") != "1":
                error_msg = page_response.get("error", f"Unexpected response format or status: {page_response}")
                raise ApiError(f"Failed to fetch vulnerabilities page {page} for scan '{scan_code}': {error_msg}", 
                              details=page_response)
            
            data = page_response.get("data")
            # Process the page results
            if isinstance(data, dict) and "list" in data:
                vuln_list = data["list"]
                if isinstance(vuln_list, list):
                    all_vulnerabilities.extend(vuln_list)
                    logger.debug(f"Added {len(vuln_list)} vulnerabilities from page {page}")
                else:
                    logger.warning(f"Unexpected vulnerability list format on page {page}: {vuln_list}")
            elif not data or (isinstance(data, dict) and not data):
                # Empty page - this is unexpected but we'll continue
                logger.warning(f"Empty data received for vulnerabilities page {page}")
            else:
                logger.warning(f"Unexpected data format for vulnerabilities page {page}: {data}")
        
        logger.debug(f"Successfully fetched all {len(all_vulnerabilities)} vulnerabilities for scan '{scan_code}'")
        return all_vulnerabilities

# Scan Ops:Reporting
    def generate_report(
        self,
        scope: str,
        project_code: str,
        scan_code: Optional[str],
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
    ) -> Union[int, requests.Response]:
        """
        Triggers report generation for a scan or project.
        Project reports are always async. Scan reports can be sync or async.
        Returns process queue ID for async, or raw response for sync scan reports.

        Args:
            scope: Either 'scan' or 'project'
            project_code: Code of the project
            scan_code: Code of the scan (required for scan scope)
            report_type: Type of report to generate
            selection_type: Optional selection type
            selection_view: Optional selection view
            disclaimer: Optional disclaimer text
            include_vex: Whether to include VEX data

        Returns:
            Union[int, requests.Response]: Process queue ID for async reports, or raw response for sync reports

        Raises:
            ValidationError: If scope is invalid or required parameters are missing
            ApiError: If there are API issues
            ProjectNotFoundError: If the project doesn't exist
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValidationError("Invalid scope provided to generate_report. Must be 'scan' or 'project'.")

        is_project_scope = (scope == "project")

        # --- Force Async for Project Scope ---
        if is_project_scope:
            use_async = True
            # Validate report type against allowed project types
            if report_type not in self.PROJECT_REPORT_TYPES:
                raise ValidationError(f"Report type '{report_type}' is not supported for project scope reports.")
        else: # scan scope
            use_async = report_type in self.ASYNC_REPORT_TYPES
            # No need to validate scan report types here, API will handle it

        async_value = "1" if use_async else "0" # Will always be "1" for project scope

        # Determine group, action, and primary code based on scope
        if is_project_scope:
            group = "projects"
            action = "generate_report"
            code_key = "project_code"
            code_value = project_code
            entity_name = f"project '{project_code}'"
            if not project_code:
                raise ValidationError("project_code is required for project scope reports.")
        else: # scan scope
            group = "scans"
            action = "generate_report"
            code_key = "scan_code"
            code_value = scan_code
            entity_name = f"scan '{scan_code}'"
            if not scan_code:
                raise ValidationError("scan_code is required for scan scope reports.")

        logger.info(f"Requesting generation of '{report_type}' report for {entity_name} (Async: {use_async})...")

        payload_data = {
            code_key: code_value,
            "report_type": report_type,
            "async": async_value,
            "include_vex": include_vex,
        }
        # Add optional parameters if provided
        if selection_type:
            payload_data["selection_type"] = selection_type
        if selection_view:
            payload_data["selection_view"] = selection_view
        if disclaimer:
            payload_data["disclaimer"] = disclaimer

        payload = {
            "group": group,
            "action": action,
            "data": payload_data
        }

        response_data = self._send_request(payload)

        # --- Response Handling ---
        if "_raw_response" in response_data:
            # This block should ONLY be reached for SYNCHRONOUS SCAN reports
            if is_project_scope:
                # This is unexpected based on the requirement that project reports are always async
                logger.error(f"API returned a synchronous response for a project report ({report_type}), which was not expected. Cannot proceed.")
                raise ApiError(f"Unexpected synchronous response received for project report '{report_type}'.")
            else:
                # Handle synchronous scan report
                raw_response = response_data["_raw_response"]
                logger.info(f"Synchronous report generation likely completed for {entity_name}. Returning raw response object.")
                return raw_response

        elif response_data.get("status") == "1" and "data" in response_data and "process_queue_id" in response_data["data"]:
            # This block handles ASYNC scan reports AND ALL project reports
            process_id = response_data["data"]["process_queue_id"]
            logger.debug(f"Report generation requested successfully (async) for {entity_name}. Process ID: {process_id}")
            return int(process_id)
        else:
            # Handle API errors (status 0 or unexpected format)
            error_msg = response_data.get("error", f"Unexpected response: {response_data}")
            if "Project does not exist" in error_msg or "row_not_found" in error_msg:
                raise ProjectNotFoundError(f"Project '{project_code}' not found")
            elif "Scan not found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(f"Failed to request report generation for {entity_name}: {error_msg}", details=response_data)

    def check_report_generation_status(
        self,
        scope: str, 
        process_id: int,
        scan_code: Optional[str] = None,
        project_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Checks the status of an asynchronous report generation process.

        Args:
            scope: Either 'scan' or 'project'
            process_id: ID of the process to check
            scan_code: Optional scan code for context
            project_code: Optional project code for context

        Returns:
            Dict[str, Any]: The process status data

        Raises:
            ValidationError: If scope is invalid
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValidationError("Invalid scope provided to check_report_generation_status.")

        group = "projects" if scope == "project" else "scans"
        entity_name = f"project '{project_code}'" if scope == "project" else f"scan '{scan_code}'"
        logger.debug(f"Checking report generation status for process {process_id} ({scope} scope)...")

        payload = {
            "group": group,
            "action": "check_status",
            "data": {
                "process_id": str(process_id),
                "type": "REPORT_GENERATION",
            }
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to check report status for process {process_id} ({entity_name}): {error_msg}", details=response)

    def download_report(self, scope: str, process_id: int):
        """
        Downloads a generated report using its process ID.
        Returns the requests.Response object containing the report content.

        Args:
            scope: Either 'scan' or 'project'
            process_id: ID of the process to download report from

        Returns:
            requests.Response: The response object containing the report content

        Raises:
            ValidationError: If scope is invalid
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValidationError("Invalid scope provided to download_report.")

        report_entity = "projects" if scope == "project" else "scans"
        logger.debug(f"Attempting to download report for process ID '{process_id}' (entity: {report_entity})...")

        payload = {
            "group": "download",
            "action": "download_report",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "report_entity": report_entity,
                "process_id": str(process_id)
            }
        }
        req_body = json.dumps(payload)
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "*/*",
        }

        logger.debug("Download API URL: %s", self.api_url)
        logger.debug("Download Request Headers: %s", headers)
        logger.debug("Download Request Body: %s", req_body)

        try:
            logger.debug(f"Initiating download request for process ID: {process_id}")
            # IMPORTANT: Do NOT use 'with' here if returning the response object
            r = self.session.post(
                self.api_url,
                headers=headers,
                data=req_body,
                stream=True, # Still use stream in case caller wants it
                timeout=1800
            )
            logger.debug(f"Download Response Status Code: {r.status_code}")
            logger.debug(f"Download Response Headers: {r.headers}")
            r.raise_for_status() # Check for HTTP errors (4xx, 5xx)

            content_type = r.headers.get('content-type', '').lower()
            content_disposition = r.headers.get('content-disposition')
            logger.info(f"Download Content-Type received: {content_type}")
            if content_disposition:
                logger.info(f"Download Content-Disposition received: {content_disposition}")

            is_likely_file_content = bool(content_disposition) or ('application/json' not in content_type)

            if not is_likely_file_content:
                # Treat as potential JSON API error
                logger.warning(f"Received JSON content type without Content-Disposition. Assuming API error message.")
                try:
                    error_json = r.json()
                    error_msg = error_json.get("error", "Unknown error")
                    logger.error(f"API error during download: {error_msg} | JSON: {error_json}")
                    raise ApiError(f"Failed to download report (process ID {process_id}): API returned error - {error_msg}", details=error_json)
                except json.JSONDecodeError as json_err:
                    logger.error(f"Failed to decode JSON error response during download: {r.text[:500]}", exc_info=True)
                    raise ApiError(f"Failed to download report (process ID {process_id}): Could not parse API error response.", details={"response_text": r.text[:500]})

            # If we reach here, it's likely the actual report content. Return the response object.
            logger.debug("Download request successful, returning response object.")
            return r # Return the response object

        except requests.exceptions.RequestException as req_err:
            logger.error(f"Failed to initiate report download request for process {process_id}: {req_err}", exc_info=True)
            raise NetworkError(f"Failed to download report (process ID {process_id}): {req_err}")
        except Exception as final_dl_err:
            logger.error(f"Unexpected error within download_report function for process {process_id}: {final_dl_err}", exc_info=True)
            raise ApiError(f"Unexpected error during report download (process ID {process_id})", details={"error": str(final_dl_err)})
