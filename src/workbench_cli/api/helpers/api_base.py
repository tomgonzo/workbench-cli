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
from ...exceptions import (
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
from .process_waiters import ProcessWaiters
from .scan_status_checkers import StatusCheckers

# Assume logger is configured in main.py
logger = logging.getLogger("workbench-cli")

class APIBase(ProcessWaiters, StatusCheckers):
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
        self.session.trust_env = False # Do not trust .netrc file

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
            # Handle network-level errors (e.g., DNS failure, refused connection)
            raise NetworkError(f"Network error while calling API: {e}") from e

        except requests.exceptions.RequestException as e:
            logger.error("API request failed: %s", e, exc_info=True)
            raise NetworkError(f"API request failed: {str(e)}", details={"error": str(e)}) 
