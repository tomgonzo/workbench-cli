# tests/unit/api/helpers/test_process_waiters.py

import pytest
import time
from unittest.mock import MagicMock, patch

from workbench_cli.api.helpers.process_waiters import ProcessWaiters
from workbench_cli.exceptions import (
    ProcessTimeoutError,
    ProcessError,
    ApiError,
    NetworkError,
    ScanNotFoundError,
)

# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock()
    mock_sess.post = mocker.MagicMock()
    mocker.patch('requests.Session', return_value=mock_sess)
    return mock_sess

@pytest.fixture
def process_waiter_inst(mock_session):
    """Create a ProcessWaiters instance with a properly mocked session."""
    # Create a concrete instance for testing
    class TestProcessWaiter(ProcessWaiters):
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
            return {"status": "FINISHED"}
    
    waiter = TestProcessWaiter(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")
    return waiter

# --- Test _wait_for_process ---
def test_wait_for_process_success(process_waiter_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        {"progress_state": "RUNNING"},
        {"progress_state": "RUNNING"},
        {"progress_state": "FINISHED"},
    ]
    with patch('time.sleep', return_value=None): # Mock sleep
        success = process_waiter_inst._wait_for_process(
            process_description="Test Process",
            check_function=mock_check_func, check_args={"arg1": "val1"},
            status_accessor=lambda data: data.get("progress_state"),
            success_values={"FINISHED"}, failure_values={"FAILED"},
            max_tries=5, wait_interval=0.01, progress_indicator=False
        )
    assert success is True
    assert mock_check_func.call_count == 3

def test_wait_for_process_timeout(process_waiter_inst, mocker):
    mock_check_func = mocker.MagicMock(return_value={"progress_state": "RUNNING"})
    with patch('time.sleep', return_value=None): # Mock sleep
        with pytest.raises(ProcessTimeoutError, match="Timeout waiting for Test Timeout"):
            process_waiter_inst._wait_for_process(
                process_description="Test Timeout",
                check_function=mock_check_func, check_args={},
                status_accessor=lambda data: data.get("progress_state"),
                success_values={"FINISHED"}, failure_values={"FAILED"},
                max_tries=3, wait_interval=0.01, progress_indicator=False
            )
    assert mock_check_func.call_count == 3

def test_wait_for_process_failure(process_waiter_inst, mocker):
    mock_check_func = mocker.MagicMock(return_value={"progress_state": "FAILED", "error": "Disk full"})
    with patch('time.sleep', return_value=None): # Mock sleep
        with pytest.raises(ProcessError, match="The Test Failure FAILED"):
            process_waiter_inst._wait_for_process(
                process_description="Test Failure",
                check_function=mock_check_func, check_args={},
                status_accessor=lambda data: data.get("progress_state"),
                success_values={"FINISHED"}, failure_values={"FAILED"},
                max_tries=5, wait_interval=0.01, progress_indicator=False
            )
    assert mock_check_func.call_count == 1 # Fails on first check

def test_wait_for_process_check_fails_retries(process_waiter_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        NetworkError("Network glitch"), # First call fails
        {"progress_state": "RUNNING"},        # Second call succeeds
        {"progress_state": "FINISHED"},       # Third call succeeds
    ]
    with patch('time.sleep', return_value=None): # Mock sleep
        success = process_waiter_inst._wait_for_process(
            process_description="Test Retry",
            check_function=mock_check_func, check_args={},
            status_accessor=lambda data: data.get("progress_state"),
            success_values={"FINISHED"}, failure_values={"FAILED"},
            max_tries=5, wait_interval=0.01, progress_indicator=False
        )
    assert success is True
    assert mock_check_func.call_count == 3

def test_wait_for_process_accessor_fails(process_waiter_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.return_value = {"wrong_key": "FINISHED"} # Status cannot be accessed
    with patch('time.sleep', return_value=None): # Mock sleep
        try:
            process_waiter_inst._wait_for_process(
                process_description="Test Accessor",
                check_function=mock_check_func, check_args={},
                status_accessor=lambda data: data["progress_state"],  # This will raise KeyError
                success_values={"FINISHED"}, failure_values={"FAILED"},
                max_tries=3, wait_interval=0.01, progress_indicator=False
            )
            pytest.fail("Expected ProcessError to be raised")
        except ProcessError as e:
            # Test will pass if a ProcessError was raised
            assert "Test Accessor ACCESS_ERROR" in str(e)
    
    # Verify the check function was called at least once
    assert mock_check_func.call_count >= 1

# --- Test wait_for_git_clone ---
def test_wait_for_git_clone_success(process_waiter_inst, mocker):
    """Test successful git clone waiting."""
    mock_responses = [
        {"data": "RUNNING"},
        {"data": "RUNNING"},
        {"data": "FINISHED"}
    ]
    
    process_waiter_inst._send_request = mocker.MagicMock(side_effect=mock_responses)
    
    with patch('time.sleep', return_value=None):
        with patch('time.time', side_effect=[0, 10]):  # Mock time for duration calculation
            result, duration = process_waiter_inst.wait_for_git_clone("scan1", 5, 3)
    
    assert result["data"] == "FINISHED"
    assert result["_duration_seconds"] == 10
    assert duration == 10
    assert process_waiter_inst._send_request.call_count == 3

def test_wait_for_git_clone_failure(process_waiter_inst, mocker):
    """Test git clone failure."""
    mock_response = {"data": "FAILED", "message": "Git error"}
    
    process_waiter_inst._send_request = mocker.MagicMock(return_value=mock_response)
    
    with patch('time.sleep', return_value=None):
        with pytest.raises(ProcessError, match="Git Clone failed for scan 'scan1'"):
            process_waiter_inst.wait_for_git_clone("scan1", 5, 3)

def test_wait_for_git_clone_timeout(process_waiter_inst, mocker):
    """Test git clone timeout."""
    mock_response = {"data": "RUNNING"}
    
    process_waiter_inst._send_request = mocker.MagicMock(return_value=mock_response)
    
    with patch('time.sleep', return_value=None):
        with pytest.raises(ProcessTimeoutError, match="Git clone timed out for scan 'scan1'"):
            process_waiter_inst.wait_for_git_clone("scan1", 3, 3)
    
    assert process_waiter_inst._send_request.call_count == 3

def test_wait_for_git_clone_api_error(process_waiter_inst, mocker):
    """Test git clone API error."""
    process_waiter_inst._send_request = mocker.MagicMock(side_effect=ApiError("API failed"))
    
    with patch('time.sleep', return_value=None):
        with pytest.raises(ApiError, match="API failed"):
            process_waiter_inst.wait_for_git_clone("scan1", 5, 3)

# --- Test wait_for_archive_extraction ---
def test_wait_for_archive_extraction_success(process_waiter_inst, mocker):
    """Test successful archive extraction waiting."""
    # Mock the get_scan_status method to return finished status on first call
    process_waiter_inst.get_scan_status = mocker.MagicMock(return_value={
        "is_finished": "1",
        "status": "FINISHED"
    })
    
    with patch('time.time', side_effect=[0, 15.0]):  # Mock time for duration calculation
        with patch('time.sleep'):  # Mock sleep to speed up test
            result, duration = process_waiter_inst.wait_for_archive_extraction("scan1", 10, 5)
    
    assert result["is_finished"] == "1"
    assert result["status"] == "FINISHED"
    assert duration == 15.0
    process_waiter_inst.get_scan_status.assert_called_once_with("EXTRACT_ARCHIVES", "scan1")

# --- Test wait_for_scan_to_finish ---
def test_wait_for_scan_to_finish_success(process_waiter_inst, mocker):
    """Test successful scan completion waiting."""
    mock_result = ({"status": "FINISHED"}, 20.0)
    process_waiter_inst._wait_for_operation_with_status = mocker.MagicMock(return_value=mock_result)
    
    result, duration = process_waiter_inst.wait_for_scan_to_finish("SCAN", "scan1", 15, 8)
    
    assert result["status"] == "FINISHED"
    assert duration == 20.0
    process_waiter_inst._wait_for_operation_with_status.assert_called_once_with(
        operation_name="KB Scan", scan_type="SCAN", scan_code="scan1", max_tries=15, wait_interval=8, should_track_files=True
    ) 