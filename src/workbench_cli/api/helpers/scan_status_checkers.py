import logging
import requests
from typing import Dict, Any
from ...exceptions import (
    ApiError,
    NetworkError,
    CompatibilityError,
    ProcessError,
    ProcessTimeoutError,
    ScanNotFoundError,
)

logger = logging.getLogger("workbench-cli")

class StatusCheckers:
    """
    Helper class for checking process statuses.
    """
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
            
    def ensure_process_can_start(
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
             raise ValueError(f"Invalid process_type '{process_type}' provided to ensure_process_can_start.")

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
        except (ApiError, NetworkError, ScanNotFoundError, CompatibilityError):
            raise
        except (ProcessError, ProcessTimeoutError):
            # Re-raise process-related errors without wrapping them
            raise
        except Exception as e:
            raise ProcessError(f"Could not verify if {process_type.lower()} can start for '{scan_code}'", details={"error": str(e)})

    def _get_process_status(self, process_type: str, scan_code: str) -> str:
        """Helper to get status for a given process type."""
        
        if process_type not in self.PROCESS_STATUS_MAP:
            raise ValueError(f"Invalid process_type '{process_type}' provided to ensure_process_can_start.")

        status_method = self.PROCESS_STATUS_MAP[process_type]
        status_data = status_method(scan_code)
        
        return status_data.get("status", "UNKNOWN")

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
