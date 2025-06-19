# tests/unit/api/helpers/test_scan_status_checkers.py

import pytest
import requests
from unittest.mock import MagicMock, patch

from workbench_cli.api.helpers.scan_status_checkers import StatusCheckers
from workbench_cli.exceptions import (
    ApiError,
    NetworkError,
    CompatibilityError,
    ProcessError,
    ProcessTimeoutError,
    ScanNotFoundError,
)

# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch('requests.Session', return_value=mock_sess)
    return mock_sess

@pytest.fixture 
def status_checker_inst(mock_session):
    """Create a StatusCheckers instance with a properly mocked session."""
    # Create a concrete instance for testing
    class TestStatusChecker(StatusCheckers):
        def __init__(self, api_url, api_user, api_token):
            self.api_url = api_url
            self.api_user = api_user
            self.api_token = api_token
            self.session = mock_session
            
        def _send_request(self, payload, timeout=1800):
            # Mock implementation
            return {}
            
        def get_scan_status(self, scan_type, scan_code):
            # Mock implementation
            return {"status": "NEW"}
            
        def wait_for_scan_to_finish(self, scan_type, scan_code, max_tries, wait_interval):
            # Mock implementation
            return {"status": "FINISHED"}, 10.0
    
    checker = TestStatusChecker(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")
    return checker

# --- Test _is_status_check_supported ---
def test_is_status_check_supported_yes(status_checker_inst):
    with patch.object(status_checker_inst, '_send_request', return_value={"status": "1"}):
        assert status_checker_inst._is_status_check_supported("scan1", "SCAN") is True

def test_is_status_check_supported_no_invalid_type(status_checker_inst):
    error_payload = {
        "status": "0", "error": "RequestData.Base.issues_while_parsing_request",
        "data": [{"code": "RequestData.Base.field_not_valid_option", "message_parameters": {"fieldname": "type"}}]
    }
    with patch.object(status_checker_inst, '_send_request', return_value=error_payload):
        assert status_checker_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES") is False

def test_is_status_check_supported_api_error(status_checker_inst):
    with patch.object(status_checker_inst, '_send_request', return_value={"status": "0", "error": "Scan not found"}):
        with pytest.raises(ApiError, match="API error during EXTRACT_ARCHIVES support check: Scan not found"):
            status_checker_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES")

def test_is_status_check_supported_network_error(status_checker_inst):
    with patch.object(status_checker_inst, '_send_request', side_effect=NetworkError("Connection failed")):
        with pytest.raises(NetworkError):
            status_checker_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES")

# --- Test standard_scan_status_accessor ---
def test_standard_scan_status_accessor_with_is_finished(status_checker_inst):
    data = {"is_finished": "1"}
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "FINISHED"
    
    data = {"is_finished": True}
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "FINISHED"

def test_standard_scan_status_accessor_with_status(status_checker_inst):
    data = {"status": "RUNNING"}
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "RUNNING"
    
    data = {"status": "running"}  # Lowercase
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "RUNNING"  # Should be uppercase

def test_standard_scan_status_accessor_unknown(status_checker_inst):
    data = {"some_other_key": "value"}
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "UNKNOWN"

def test_standard_scan_status_accessor_access_error(status_checker_inst):
    data = 123  # Not a dict, will cause AttributeError
    status = status_checker_inst._standard_scan_status_accessor(data)
    assert status == "ACCESS_ERROR"

# --- Test ensure_process_can_start ---
def test_ensure_process_can_start_when_new(status_checker_inst, mocker):
    """Test ensure_process_can_start when the initial status is NEW."""
    mocker.patch.object(status_checker_inst, 'get_scan_status', return_value={"status": "NEW"})
    
    # Should not raise any exception
    status_checker_inst.ensure_process_can_start("SCAN", "scan1", 30, 5)

def test_ensure_process_can_start_when_finished(status_checker_inst, mocker):
    """Test ensure_process_can_start when the initial status is FINISHED."""
    mocker.patch.object(status_checker_inst, 'get_scan_status', return_value={"status": "FINISHED"})
    
    # Should not raise any exception
    status_checker_inst.ensure_process_can_start("SCAN", "scan1", 30, 5)

def test_ensure_process_can_start_when_failed(status_checker_inst, mocker):
    """Test ensure_process_can_start when the initial status is FAILED."""
    mocker.patch.object(status_checker_inst, 'get_scan_status', return_value={"status": "FAILED"})
    
    # Should not raise any exception
    status_checker_inst.ensure_process_can_start("SCAN", "scan1", 30, 5)

def test_ensure_process_can_start_when_running_then_wait_success(status_checker_inst, mocker):
    """Test ensure_process_can_start when status is running but wait succeeds."""
    mocker.patch.object(status_checker_inst, 'get_scan_status', return_value={"status": "RUNNING"})
    mocker.patch.object(status_checker_inst, 'wait_for_scan_to_finish', return_value=None)
    
    status_checker_inst.ensure_process_can_start("SCAN", "scan1", 30, 5)
    
    # Verify wait_for_scan_to_finish was called
    status_checker_inst.wait_for_scan_to_finish.assert_called_once_with("SCAN", "scan1", 30, 5)

def test_ensure_process_can_start_when_running_then_wait_error(status_checker_inst, mocker):
    """Test ensure_process_can_start when status is running and wait fails."""
    mocker.patch.object(status_checker_inst, 'get_scan_status', return_value={"status": "RUNNING"})
    mocker.patch.object(status_checker_inst, 'wait_for_scan_to_finish', side_effect=ProcessTimeoutError("Timeout"))

    with pytest.raises(ProcessError, match="Could not start SCAN for 'scan1' because waiting for the existing process failed: Timeout"):
        status_checker_inst.ensure_process_can_start("SCAN", "scan1", 30, 5)
    
    # Verify wait_for_scan_to_finish was called
    status_checker_inst.wait_for_scan_to_finish.assert_called_once_with("SCAN", "scan1", 30, 5)

def test_ensure_process_can_start_other_status(status_checker_inst, mocker):
    """Test ensure_process_can_start with a status that isn't allowed."""
    # Mocking get_scan_status to return a status that's not in the allowed list
    mocker.patch.object(
        status_checker_inst,
        'get_scan_status',
        return_value={"status": "NOT_ALLOWED_STATUS"}
    )
    
    with pytest.raises(CompatibilityError):
        # The helper's ensure_process_can_start method should raise a ProcessError
        # for statuses that are not NEW, FINISHED, FAILED, CANCELLED, or RUNNING/QUEUED.
        status_checker_inst.ensure_process_can_start("SCAN", "scan1", 1, 1)

def test_ensure_process_can_start_scan_not_found(status_checker_inst, mocker):
    """Test ensure_process_can_start when the scan is not found."""
    mocker.patch.object(status_checker_inst, 'get_scan_status', side_effect=ScanNotFoundError("Not Found"))
    
    with pytest.raises(ScanNotFoundError):
        status_checker_inst.ensure_process_can_start("SCAN", "scan1", 30, 5)

def test_ensure_process_can_start_invalid_type(status_checker_inst):
    """Test that an invalid process type raises a ValueError."""
    with pytest.raises(ValueError, match="Invalid process_type 'INVALID' provided to ensure_process_can_start"):
        status_checker_inst.ensure_process_can_start("INVALID", "scan1", 30, 5) 