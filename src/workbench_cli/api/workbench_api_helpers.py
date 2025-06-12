import os
import re
import json
import time
import logging
import requests
import zipfile
import tempfile
import shutil
import io
import base64
import pathlib
from typing import Dict, List, Optional, Union, Any, Callable, Generator, Tuple
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

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-cli")

class WorkbenchAPIHelpers:
    """
    Base class with helper methods for Workbench API interactions.
    Contains methods that handle the "how" of API operations.
    """
    
    def __init__(self, api_url: str, api_user: str, api_token: str):
        """
        Initialize the base Workbench API client with authentication details.
        
        Args:
            api_url: URL to the API endpoint
            api_user: API username
            api_token: API token/key
        """
        # Ensure the API URL ends with api.php
        if not api_url.endswith('/api.php'):
            self.api_url = api_url.rstrip('/') + '/api.php'
            print(f"Warning: API URL adjusted to: {self.api_url}")
        else:
            self.api_url = api_url
        self.api_user = api_user
        self.api_token = api_token
        self.session = requests.Session()  # Use a session for potential connection reuse

## General API Operations
    def _send_request(self, payload: dict, timeout: int = 1800) -> dict:
        """
        Sends a POST request to the Workbench API.
        Handles expected non-JSON responses for synchronous operations.
        
        Args:
            payload: The request payload
            timeout: Request timeout in seconds
        
        Returns:
            Dict with response data or a special _raw_response key for non-JSON responses
            
        Raises:
            NetworkError: For connection issues, timeouts, etc.
            AuthenticationError: For authentication failures
            ApiError: For API-level errors
        """
        headers = {
            "Accept": "*/*", # Keep broad accept for now
            "Content-Type": "application/json; charset=utf-8",
        }
        payload.setdefault("data", {})
        payload["data"]["username"] = self.api_user
        payload["data"]["key"] = self.api_token

        req_body = json.dumps(payload)
        logger.debug("API URL: %s", self.api_url)
        logger.debug("Request Headers: %s", headers)
        logger.debug("Request Body: %s", req_body)

        try:
            response = self.session.post(
                self.api_url, headers=headers, data=req_body, timeout=timeout
            )
            logger.debug("Response Status Code: %s", response.status_code)
            logger.debug("Response Headers: %s", response.headers)
            # Log first part of text regardless of JSON success/failure
            logger.debug(f"Response Text (first 500 chars): {response.text[:500] if hasattr(response, 'text') else '(No text)'}")
            
            # Handle authentication errors
            if response.status_code == 401:
                raise AuthenticationError("Invalid credentials or expired token")
            
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' in content_type:
                try:
                    parsed_json = response.json()
                    # Check for API-level errors indicated by status='0'
                    if isinstance(parsed_json, dict) and parsed_json.get("status") == "0":
                        error_msg = parsed_json.get("error", "Unknown API error")
                        logger.debug(f"API returned status 0 JSON: {error_msg} | Payload: {payload}")

                        is_invalid_type_probe = False
                        if (payload.get("action") == "check_status" and
                            error_msg == "RequestData.Base.issues_while_parsing_request" and
                            isinstance(parsed_json.get("data"), list) and
                            len(parsed_json["data"]) > 0 and
                            isinstance(parsed_json["data"][0], dict) and
                            parsed_json["data"][0].get("code") == "RequestData.Base.field_not_valid_option" and
                            parsed_json["data"][0].get("message_parameters", {}).get("fieldname") == "type"):
                            is_invalid_type_probe = True
                            logger.debug("Detected 'invalid type option' error during check_status probe.")

                        # Determine if this error is expected and non-fatal
                        is_existence_check = payload.get("action") == "get_information"
                        is_create_action = payload.get("action") == "create"
                        project_not_found = (is_existence_check and payload.get("group") == "projects" and error_msg == "Project does not exist")
                        scan_not_found = (is_existence_check and payload.get("group") == "scans" and error_msg == "Classes.TableRepository.row_not_found")
                        project_already_exists = (is_create_action and payload.get("group") == "projects" and "Project code already exists" in error_msg)
                        scan_already_exists = (is_create_action and payload.get("group") == "scans" and ("Scan code already exists" in error_msg or "Legacy.controller.scans.code_already_exists" in error_msg))

                        # --- Include is_invalid_type_probe in non-fatal check ---
                        if not (project_not_found or scan_not_found or project_already_exists or scan_already_exists or is_invalid_type_probe):
                            logger.error(f"Unhandled API Error (status 0 JSON): {error_msg} | Payload: {payload}")
                            
                            # Check for git repository access error
                            if (parsed_json.get("error") == "RequestData.Base.issues_while_parsing_request" and 
                                isinstance(parsed_json.get("data"), list) and len(parsed_json["data"]) > 0):
                                
                                for issue in parsed_json["data"]:
                                    # Check for git repository access errors
                                    if (issue.get("code") == "RequestData.Base.issue_with_executing_command" and 
                                        "git_repo_url" in issue.get("message", "") and 
                                        "git ls-remote" in issue.get("message", "")):
                                        
                                        # Get detailed error information
                                        git_url = payload.get("data", {}).get("git_repo_url", "the repository")
                                        git_error = issue.get("message_parameters", {}).get("out", "Unknown Git error")
                                        
                                        # Raise specific error with clear message
                                        raise ApiError(
                                            f"Git repository access error: Workbench failed to create the scan because the Git repository could not be reached. "
                                            f"Error from Git: {git_error}", 
                                            code="git_repository_access_error",
                                            details=issue.get("message_parameters", {})
                                        )
                            
                        # If no specific error was detected, raise the generic API error
                        raise ApiError(error_msg, code=parsed_json.get("code"))
                        # Return the status 0 JSON for expected non-fatal errors

                    return parsed_json # Return successfully parsed JSON (status 1 or expected status 0)

                except json.JSONDecodeError as e:
                    # Content-Type was JSON but decoding failed - this is an error
                    logger.error(f"Failed to decode JSON response despite Content-Type being JSON: {response.text[:500]}", exc_info=True)
                    raise ApiError(f"Invalid JSON received from API: {e.msg}", details={"response_text": response.text[:500]})
            else:
                # Content-Type is NOT JSON. Assume it might be a direct synchronous response (like HTML report).
                # Return the raw response object for the caller (generate_report) to handle.
                logger.info(f"Received non-JSON Content-Type '{content_type}'. Returning raw response object.")
                # Use a special key to indicate this isn't a normal parsed response
                return {"_raw_response": response}

        except requests.exceptions.ConnectionError as e:
            logger.error("API connection failed: %s", e, exc_info=True)
            raise NetworkError("Failed to connect to the API server", details={"error": str(e)})
        except requests.exceptions.Timeout as e:
            logger.error("API request timed out: %s", e, exc_info=True)
            raise NetworkError("Request to API server timed out", details={"error": str(e)})
        except requests.exceptions.RequestException as e:
            logger.error("API request failed: %s", e, exc_info=True)
            raise NetworkError(f"API request failed: {str(e)}", details={"error": str(e)})

## Scan Ops: Check Scan Status
    def _is_status_check_supported(self, scan_code: str, process_type: str) -> bool:
        """
        Checks if the Workbench instance likely supports check_status for a given process type
        by probing the API and analyzing the response, including specific error codes.

        Args:
            scan_code: The code of the scan to check against.
            process_type: The process type string (e.g., "EXTRACT_ARCHIVES").

        Returns:
            True if the check_status call for the type seems supported, False otherwise.

        Raises:
            ApiError: If the check_status call fails for reasons other than a recognized unsupported type error.
            NetworkError: If there are network connectivity issues.
        """
        logger.debug(f"Probing check_status support for type '{process_type}' on scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "scan_code": scan_code,
                "type": process_type.upper(),
            },
        }
        try:
            # Short timeout is sufficient for the probe.
            response = self._send_request(payload, timeout=30)

            # If status is "1", the API understood the request type.
            if response.get("status") == "1":
                logger.debug(f"check_status for type '{process_type}' appears to be supported (API status 1).")
                return True

            # --- Check for specific 'invalid type' error structure ---
            elif response.get("status") == "0":
                error_code = response.get("error")
                data_list = response.get("data")

                # Check for the specific error structure indicating an invalid 'type' option
                if (error_code == "RequestData.Base.issues_while_parsing_request" and
                    isinstance(data_list, list) and len(data_list) > 0 and
                    isinstance(data_list[0], dict) and
                    data_list[0].get("code") == "RequestData.Base.field_not_valid_option" and
                    data_list[0].get("message_parameters", {}).get("fieldname") == "type"):

                    logger.warning(f"This version of Workbench does not support check_status for '{process_type}'. ")

                    # Optionally log the valid types listed by the API
                    valid_options = data_list[0].get("message_parameters", {}).get("options")
                    if valid_options:
                        logger.debug(f"API reported valid types are: [{valid_options}]")
                    return False
                else:
                    # It's a different status 0 error (e.g., scan not found), raise it.
                    logger.error(f"API error during {process_type} support check (but not an invalid type error): {error_code} - {response.get('message')}")
                    raise ApiError(f"API error during {process_type} support check: {error_code} - {response.get('message', 'No details')}", details=response)

            else:
                # Unexpected response format (neither status 1 nor 0)
                logger.warning(f"Unexpected response format during {process_type} support check: {response}")
                # Assume not supported to be safe
                return False

        except requests.exceptions.RequestException as e:
            # This block now primarily catches network errors or unexpected exceptions from _send_request.
            # We add a fallback check on the exception message just in case _send_request's logic changes.
            error_msg_lower = str(e).lower()
            if "requestdata.base.field_not_valid_option" in error_msg_lower and "type" in error_msg_lower:
                logger.warning(
                    f"Workbench likely does not support check_status for type '{process_type}'. "
                    f"Skipping status check. (Detected via exception: {e})"
                )
                return False
            else:
                # Different error (network, scan not found, etc.), re-raise it.
                logger.error(f"Unexpected exception during {process_type} support check: {e}", exc_info=False)
                if isinstance(e, NetworkError):
                    raise
                raise ApiError(f"Unexpected error during {process_type} support check", details={"error": str(e)}) from e

    def _standard_scan_status_accessor(self, data: Dict[str, Any]) -> str:
        """
        Standard status accessor for extracting status from API responses.
        Works with responses from SCAN, DEPENDENCY_ANALYSIS, EXTRACT_ARCHIVES and other operations.
        
        This method handles various status formats and normalizes them:
        1. Checks if 'is_finished' flag indicates completion (returns "FINISHED")
        2. Falls back to the 'status' field if present
        3. Returns "UNKNOWN" if neither is available
        4. Handles errors gracefully by returning "ACCESS_ERROR"
        
        Args:
            data: Response data dictionary from an API call
            
        Returns:
            str: Normalized uppercase status string ("FINISHED", "RUNNING", "QUEUED", "FAILED", etc.)
        """
        try:
            # Some API endpoints use is_finished=1/true to indicate completion
            is_finished_flag = data.get("is_finished")
            is_finished = str(is_finished_flag) == "1" or is_finished_flag is True

            # If finished, return "FINISHED" (using the hardcoded success value)
            if is_finished:
                return "FINISHED"

            # Otherwise, return the value of the 'status' key (or UNKNOWN)
            # Make sure it's uppercase for consistent comparison
            status = data.get("status", "UNKNOWN")
            if status:
                return status.upper()
            return "UNKNOWN"
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Error accessing status keys in data: {data}", exc_info=True)
            return "ACCESS_ERROR" # Use the ACCESS_ERROR state
            
    def assert_process_can_start(
        self,
        process_type: str,
        scan_code: str,
        wait_max_tries: int,
        wait_interval: int
    ):
        """
        Checks if a SCAN or DEPENDENCY_ANALYSIS can be started.
        If the process is currently QUEUED or RUNNING, it waits for it to finish.

        Args:
            process_type: Type of process to check (SCAN or DEPENDENCY_ANALYSIS)
            scan_code: Code of the scan to check
            wait_max_tries: Max attempts to wait if process is running/queued.
            wait_interval: Seconds between wait attempts.

        Raises:
            CompatibilityError: If the process cannot be started due to incompatible state
            ProcessError: If there are process-related issues
            ApiError: If there are API issues
            NetworkError: If there are network issues
            ScanNotFoundError: If the scan doesn't exist
        """
        process_type_upper = process_type.upper()
        if process_type_upper not in ["SCAN", "DEPENDENCY_ANALYSIS"]:
             raise ValueError(f"Invalid process_type '{process_type}' provided to assert_process_can_start.")

        try:
            scan_status = self.get_scan_status(process_type, scan_code)
            # Use the standard accessor for consistent status checking
            current_status = self._standard_scan_status_accessor(scan_status)

            # If queued or running, wait for it to finish first
            if current_status in ["QUEUED", "RUNNING"]: 
                print() # Newline before waiting message
                print(f"Existing {process_type} for '{scan_code}' is {current_status}. Waiting for it to complete...")
                logger.info(f"Existing {process_type} for '{scan_code}' is {current_status}. Waiting...")
                try:
                    self.wait_for_scan_to_finish(process_type, scan_code, wait_max_tries, wait_interval)
                    print(f"Previous {process_type} for '{scan_code}' finished. Proceeding...")
                    logger.info(f"Previous {process_type} for '{scan_code}' finished.")
                    # No need to re-check status, wait_for_scan handles terminal states
                    return # Allow proceeding
                except (ProcessTimeoutError, ProcessError) as wait_err:
                    # If waiting failed, we cannot start the new process
                    raise ProcessError(f"Could not start {process_type} for '{scan_code}' because waiting for the existing process failed: {wait_err}", details=getattr(wait_err, 'details', None)) from wait_err

            # Allow starting if NEW, FINISHED, FAILED, or CANCELLED
            allowed_statuses = ["NEW", "FINISHED", "FAILED", "CANCELLED"]
            if current_status not in allowed_statuses:
                raise CompatibilityError(
                    f"Cannot start {process_type.lower()} for '{scan_code}'. Current status is {current_status} (Must be one of {allowed_statuses})."
                )
            logger.debug(f"The {process_type} for '{scan_code}' can start (Current status: {current_status}).")
        except (ApiError, NetworkError, ScanNotFoundError):
            raise
        except Exception as e:
            raise ProcessError(f"Could not verify if {process_type.lower()} can start for '{scan_code}'", details={"error": str(e)})

## Scan Ops: Waiting for Processes
    def _wait_for_process(
        self,
        process_description: str,
        check_function: callable,
        check_args: Dict[str, Any],
        status_accessor: callable,
        success_values: set,
        failure_values: set,
        max_tries: int,
        wait_interval: int,
        progress_indicator: bool = True
    ):
        """
        Generic process status checking and waiting function.
        Repeatedly calls check_function until success, failure, or timeout.
        
        Args:
            process_description: Human-readable description of the process being waited for
            check_function: Function to call to check status
            check_args: Arguments to pass to check_function
            status_accessor: Function to extract status from check_function's result
            success_values: Set of status values indicating success
            failure_values: Set of status values indicating failure
            max_tries: Maximum number of status checks before timeout
            wait_interval: Seconds to wait between status checks
            progress_indicator: Whether to print progress indicators (dots)
            
        Returns:
            True if the process succeeded (status in success_values)
            
        Raises:
            ProcessTimeoutError: If max_tries is reached before success/failure
            ProcessError: If status is in failure_values
        """
        logger.debug(f"Waiting for {process_description}...")
        last_status = "UNKNOWN"

        for i in range(max_tries):
            status_data = None
            current_status = "UNKNOWN"

            try:
                status_data = check_function(**check_args)
                try:
                    current_status_raw = status_accessor(status_data)
                    current_status = str(current_status_raw).upper()
                except Exception as access_err:
                    logger.warning(f"Error executing status_accessor during {process_description} check: {access_err}. Response data: {status_data}", exc_info=True)
                    current_status = "ACCESS_ERROR" # Treat as failure

            except Exception as e:
                print()
                print(f"Attempt {i+1}/{max_tries}: Error checking status for {process_description}: {e}")
                print(f"Retrying in {wait_interval} seconds...")
                logger.warning(f"Error calling check_function for {process_description}", exc_info=False)
                time.sleep(wait_interval)
                continue

            # Check for Success
            if current_status in success_values:
                print()
                logger.debug(f"{process_description} completed successfully (Status: {current_status}).")
                return True

            # Check for Failure (includes ACCESS_ERROR)
            if current_status in failure_values or current_status == "ACCESS_ERROR":
                print() # Newline after dots/status
                base_error_msg = f"The {process_description} {current_status}"
                error_detail = ""
                if isinstance(status_data, dict):
                    error_detail = status_data.get("error", status_data.get("message", status_data.get("info", "")))
                if error_detail:
                    base_error_msg += f". Detail: {error_detail}"
                raise ProcessError(base_error_msg, details=status_data)

            # Basic Status Printing
            if current_status != last_status or i < 2 or i % 10 == 0:
                print()
                print(f"{process_description} status: {current_status}. Attempt {i+1}/{max_tries}.", end="", flush=True)
                last_status = current_status
            elif progress_indicator:
                print(".", end="", flush=True)

            time.sleep(wait_interval)

        print()
        raise ProcessTimeoutError(
            f"Timeout waiting for {process_description} to complete after {max_tries * wait_interval} seconds (Last Status: {last_status}).",
            details={"last_status": last_status, "max_tries": max_tries, "wait_interval": wait_interval, "last_data": status_data}
        )
    
    def wait_for_git_clone(self, scan_code: str, max_tries: int, wait_interval: int) -> Tuple[Dict[str, Any], float]:
        """
        Waits for a Git clone operation to complete.
        
        Args:
            scan_code: The code of the scan to wait for.
            max_tries: Maximum number of status check attempts.
            wait_interval: Seconds to wait between status checks (ignored, fixed at 3 seconds).
            
        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing the final status data and the duration in seconds
            
        Raises:
            ProcessTimeoutError: If the maximum number of tries is exceeded.
            ProcessError: If the Git clone process fails.
            ApiError: If the API call fails.
            NetworkError: If there's a network issue.
        """
        print("\nWaiting for Git Clone to complete...")
        logger.debug(f"Waiting for Git clone to complete for scan '{scan_code}'...")
        
        # Use fixed 3-second wait interval for git clone operations
        git_wait_interval = 3
        
        last_status = "UNKNOWN"
        client_start_time = time.time()  # Start tracking client-side duration
        status_data = {}
        
        for i in range(max_tries):
            try:
                response = self._send_request({
                    "group": "scans",
                    "action": "check_status_download_content_from_git",
                    "data": {"scan_code": scan_code}
                })
                
                # Extract status
                status = str(response.get("data", "UNKNOWN")).upper()
                status_data = response
                
                # Success case
                if status == "FINISHED":
                    logger.debug(f"Git Clone for scan '{scan_code}' completed successfully.")
                    # Calculate duration
                    duration = time.time() - client_start_time
                    # Add duration to status_data for reference
                    status_data["_duration_seconds"] = duration
                    return status_data, duration
                    
                # Failure case
                if status in ["FAILED", "ERROR"]:
                    print(f"\nGit Clone failed.")
                    logger.error(f"Git Clone failed for scan '{scan_code}'")
                    # If needed, the full message is available in the response
                    message = response.get("message", "")
                    raise ProcessError(f"Git Clone failed for scan '{scan_code}'", 
                                      details={"status": status, "message": message})
                
                # Progress reporting
                # Show full status on first attempts or when status changes
                if status != last_status or i < 2 or i % 10 == 0:
                    print()
                    print(f"Git clone status: {status}. Attempt {i+1}/{max_tries}", end="", flush=True)
                    last_status = status
                else:
                    # Just show a dot for minor updates
                    print(".", end="", flush=True)
                    
                time.sleep(git_wait_interval)
                
            except (ApiError, NetworkError) as e:
                logger.error(f"API/Network error during Git clone status check for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nError checking Git clone status: {e}")
                raise
            except ProcessError:
                # Re-raise ProcessError directly
                raise
            except Exception as e:
                logger.error(f"Unexpected error checking Git clone status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nUnexpected error checking Git clone status: {e}")
                raise ProcessError(f"Error during Git clone operation for scan '{scan_code}'", details={"error": str(e)})
        
        # If we exhaust all tries
        logger.error(f"Timed out waiting for Git clone to complete for scan '{scan_code}' after {max_tries*git_wait_interval} seconds")
        print("\nTimed out waiting for Git clone to complete")
        raise ProcessTimeoutError(f"Git clone timed out for scan '{scan_code}' after {max_tries*git_wait_interval} seconds", 
                                 details={"max_tries": max_tries, "wait_interval": git_wait_interval})
    
    def wait_for_archive_extraction(
        self,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ) -> Tuple[Dict[str, Any], float]:
        """
        Wait for archive extraction to complete.
        
        Args:
            scan_code: The code of the scan to check
            scan_number_of_tries: Maximum number of attempts
            scan_wait_time: Time to wait between attempts (ignored, fixed at 3 seconds)
            
        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing the final status data and the duration in seconds
            
        Raises:
            ProcessTimeoutError: If the process times out
            ProcessError: If the process fails
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Waiting for archive extraction to complete for scan '{scan_code}'...")
        
        # Use fixed 3-second wait interval for archive extraction
        archive_wait_interval = 3
        
        last_status = "UNKNOWN"
        last_state = ""
        last_step = ""
        client_start_time = time.time()  # Start tracking client-side duration
        status_data = {}
        
        for i in range(scan_number_of_tries):
            try:
                # Get current status from API
                status_data = self.get_scan_status("EXTRACT_ARCHIVES", scan_code)
                
                # Extract key information
                is_finished = str(status_data.get("is_finished", "0")) == "1" or status_data.get("is_finished") is True
                current_status = status_data.get("status", "UNKNOWN").upper()
                current_state = status_data.get("state", "")
                percentage = status_data.get("percentage_done", "")
                current_step = status_data.get("current_step", "")
                current_file = status_data.get("current_filename", "")
                info = status_data.get("info", "")
                
                # If finished flag is set, use FINISHED status
                if is_finished:
                    current_status = "FINISHED"
                
                # Only print a new line when status, state, or step changes
                details_changed = (
                    current_status != last_status or 
                    current_state != last_state or 
                    current_step != last_step
                )
                
                # Print a new line on first status check
                if i == 0:
                    details_changed = True
                
                # Check for success (finished)
                if current_status == "FINISHED":
                    print("\nArchive Extraction completed successfully.")
                    logger.debug(f"Archive extraction for scan '{scan_code}' completed successfully")
                    # Calculate duration
                    duration = time.time() - client_start_time
                    # Add duration to status_data for reference
                    status_data["_duration_seconds"] = duration
                    return status_data, duration
                
                # Check for failure
                if current_status in ["FAILED", "CANCELLED"]:
                    error_msg = f"Archive Extraction {current_status}"
                    if info:
                        error_msg += f" - Detail: {info}"
                    print(f"\n{error_msg}")
                    logger.error(f"Archive extraction for scan '{scan_code}' failed: {error_msg}")
                    raise ProcessError(error_msg, details=status_data)
                
                # Progress reporting
                if details_changed:
                    print()
                    
                    # Construct a detailed status message
                    status_msg = f"Archive Extraction status: {current_status}"
                    if current_state:
                        status_msg += f" ({current_state})"
                    if percentage:
                        status_msg += f" - {percentage}"
                    if current_step:
                        status_msg += f" - Step: {current_step}"
                    if current_file:
                        status_msg += f" - File: {current_file}"
                        
                    print(f"{status_msg}. Attempt {i+1}/{scan_number_of_tries}", end="", flush=True)
                    
                    # Update last values
                    last_status = current_status
                    last_state = current_state
                    last_step = current_step
                else:
                    # Just show a dot for minor updates
                    print(".", end="", flush=True)
                
                time.sleep(archive_wait_interval)
                
            except (ApiError, NetworkError, ScanNotFoundError) as e:
                logger.error(f"Error checking archive extraction status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nError checking Archive Extraction status: {e}")
                raise
            except ProcessError:
                # Re-raise ProcessError directly
                raise
            except Exception as e:
                logger.error(f"Unexpected error checking archive extraction status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nUnexpected error during Archive Extraction status check: {e}")
                raise ProcessError(f"Error during archive extraction for scan '{scan_code}'", details={"error": str(e)})
                
        # If we exhaust all tries
        logger.error(f"Timed out waiting for archive extraction to complete for scan '{scan_code}' after {scan_number_of_tries*archive_wait_interval} seconds")
        print(f"\nTimed out waiting for Archive Extraction to complete")
        raise ProcessTimeoutError(
            f"Archive extraction timed out for scan '{scan_code}' after {scan_number_of_tries*archive_wait_interval} seconds",
            details={"last_status": last_status, "max_tries": scan_number_of_tries, "wait_interval": archive_wait_interval}
        )
        
    def wait_for_scan_to_finish(
        self,
        scan_type: str,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ) -> Tuple[Dict[str, Any], float]:
        """
        Wait for a scan to complete. Delegates to the consolidated implementation with appropriate parameters.
        
        Args:
            scan_type: Type of scan ("SCAN" or "DEPENDENCY_ANALYSIS")
            scan_code: Code of the scan to check
            scan_number_of_tries: Maximum number of attempts
            scan_wait_time: Time to wait between attempts
            
        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing the final status data and the duration in seconds
            
        Raises:
            ProcessTimeoutError: If the process times out
            ProcessError: If the process fails
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        if scan_type == "SCAN":
            operation_name = "KB Scan"
            should_track_files = True
        elif scan_type == "DEPENDENCY_ANALYSIS":
            operation_name = "Dependency Analysis"
            should_track_files = False
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")
            
        return self._wait_for_operation_with_status(
            operation_name=operation_name,
            scan_type=scan_type,
            scan_code=scan_code,
            max_tries=scan_number_of_tries,
            wait_interval=scan_wait_time,
            should_track_files=should_track_files
        )
            
    def _wait_for_operation_with_status(
        self,
        operation_name: str,
        scan_type: str,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
        should_track_files: bool = False
    ) -> Tuple[Dict[str, Any], float]:
        """
        Consolidated implementation for waiting on scan operations with customized progress display.
        
        Args:
            operation_name: Human-readable name of the operation (e.g., "KB Scan")
            scan_type: API type of the scan ("SCAN" or "DEPENDENCY_ANALYSIS")
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Time to wait between attempts
            should_track_files: Whether to track file counting information
            
        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing the final status data and the duration in seconds
            
        Raises:
            ProcessTimeoutError: If the process times out
            ProcessError: If the process fails
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Waiting for {scan_type} operation to complete for scan '{scan_code}'...")
        
        # Initialize tracking variables
        last_status = "UNKNOWN"
        last_state = ""
        last_step = ""
        start_time = None
        client_start_time = time.time()  # Start tracking client-side duration
        status_data = None
        
        for i in range(max_tries):
            try:
                # Get current status from API
                status_data = self.get_scan_status(scan_type, scan_code)
                
                # Extract key information
                current_status = status_data.get("status", "UNKNOWN").upper()
                current_state = status_data.get("state", "")
                current_step = status_data.get("current_step", "")
                
                # Extract additional information specific to the scan type
                file_count_info = ""
                total_files = 0
                current_file_idx = 0
                percentage = ""
                
                if should_track_files:
                    # Extract file processing information (KB scan only)
                    total_files = status_data.get("total_files", 0)
                    current_file_idx = status_data.get("current_file", 0)
                    percentage = status_data.get("percentage_done", "")
                    
                    # Create file progress info if available
                    if total_files and int(total_files) > 0:
                        # Display progress as a fraction with percentage
                        file_count_info = f" - File {current_file_idx}/{total_files}"
                        if percentage:
                            file_count_info += f" ({percentage})"
                
                # Get operation start time from API if available
                api_start_time = status_data.get("started")
                if api_start_time and not start_time:
                    start_time = api_start_time
                
                # Only print a new line when status, state, or step changes
                details_changed = (
                    current_status != last_status or 
                    current_state != last_state or 
                    current_step != last_step
                )
                
                # Print a new line on first status check
                if i == 0:
                    details_changed = True
                    
                # Print a new line every 10 status checks to update the user
                show_periodic_update = i > 0 and i % 10 == 0 and current_status == "RUNNING"
                
                # Check for success (finished)
                if current_status == "FINISHED":
                    # Calculate duration using API timestamps if available
                    duration_str = ""
                    api_finish_time = status_data.get("finished")
                    api_duration_sec = None
                    
                    if start_time and api_finish_time:
                        try:
                            # Parse timestamps and calculate duration
                            from datetime import datetime
                            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                            finish_dt = datetime.strptime(api_finish_time, "%Y-%m-%d %H:%M:%S")
                            api_duration_sec = (finish_dt - start_dt).total_seconds()
                            
                            # Format duration as a string
                            minutes, seconds = divmod(api_duration_sec, 60)
                            hours, minutes = divmod(minutes, 60)
                            if hours > 0:
                                duration_str = f" (Completed in {int(hours)}h {int(minutes)}m {int(seconds)}s)"
                            elif minutes > 0:
                                duration_str = f" (Completed in {int(minutes)}m {int(seconds)}s)"
                            else:
                                duration_str = f" (Completed in {int(seconds)}s)"
                        except Exception as e:
                            logger.debug(f"Error calculating duration: {e}")
                    
                    print(f"\n{operation_name} completed successfully{duration_str}.")
                    logger.debug(f"{scan_type} for scan '{scan_code}' completed successfully")
                    
                    # Calculate client-side duration as fallback
                    client_duration = time.time() - client_start_time
                    
                    # Prefer API-reported duration if available, otherwise use client-side duration
                    final_duration = api_duration_sec if api_duration_sec is not None else client_duration
                    
                    # Add duration to status_data for reference
                    status_data["_duration_seconds"] = final_duration
                    
                    return status_data, final_duration
                
                # Check for failure
                if current_status in ["FAILED", "CANCELLED"]:
                    error_msg = f"{operation_name} {current_status}"
                    info = status_data.get("info", "")
                    if info:
                        error_msg += f" - Detail: {info}"
                    print(f"\n{error_msg}")
                    logger.error(f"{scan_type} for scan '{scan_code}' failed: {error_msg}")
                    raise ProcessError(error_msg, details=status_data)
                
                # Progress reporting
                if details_changed or show_periodic_update:
                    print()
                    
                    # Construct a detailed status message
                    status_msg = f"{operation_name} status: {current_status}"
                    if current_state:
                        status_msg += f" ({current_state})"
                    
                    # Include file progress information for KB scan
                    if file_count_info:
                        status_msg += file_count_info
                    elif percentage:
                        status_msg += f" - {percentage}"
                    
                    # Show current step
                    if current_step:
                        status_msg += f" - Step: {current_step}"
                        
                    print(f"{status_msg}. Attempt {i+1}/{max_tries}", end="", flush=True)
                    
                    # Update last values
                    last_status = current_status
                    last_state = current_state
                    last_step = current_step
                else:
                    # Just show a dot for minor updates
                    print(".", end="", flush=True)
                
                time.sleep(wait_interval)
                
            except (ApiError, NetworkError, ScanNotFoundError) as e:
                logger.error(f"Error checking {scan_type} status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nError checking {operation_name} status: {e}")
                raise
            except ProcessError:
                # Re-raise ProcessError directly
                raise
            except Exception as e:
                logger.error(f"Unexpected error checking {scan_type} status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nUnexpected error during {operation_name} status check: {e}")
                raise ProcessError(f"Error during {scan_type} operation for scan '{scan_code}'", details={"error": str(e)})
                
        # If we exhaust all tries
        logger.error(f"Timed out waiting for {scan_type} to complete for scan '{scan_code}' after {max_tries} attempts")
        print(f"\nTimed out waiting for {operation_name} to complete")
        raise ProcessTimeoutError(
            f"{scan_type} timed out for scan '{scan_code}' after {max_tries} attempts",
            details={"last_status": last_status, "max_tries": max_tries, "wait_interval": wait_interval}
        )

    def get_scan_status(self, scan_type: str, scan_code: str) -> dict:
        """
        Retrieve scan status. This method should be overridden by subclasses.
        
        Args:
            scan_type: Type of scan operation (SCAN or DEPENDENCY_ANALYSIS)
            scan_code: Code of the scan to check
            
        Returns:
            dict: The scan status data
            
        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
            NotImplementedError: If called on the base class
        """
        raise NotImplementedError("get_scan_status must be implemented by subclasses")
