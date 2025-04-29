# tests/test_workbench.py

import pytest
import requests
import os
import json # Needed for JSONDecodeError test
import argparse # Needed for mock_params fixture in moved tests
import time # Needed for time.sleep mock in moved tests
from unittest.mock import MagicMock, patch, mock_open

# Import from the package structure
from workbench_agent.api import Workbench
# Removed utils imports as tests were moved: _save_report_content, _resolve_project, _resolve_scan, _ensure_scan_compatibility
from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError,
    CompatibilityError
)

# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch('requests.Session', return_value=mock_sess)
    return mock_sess

@pytest.fixture
def workbench_inst(mock_session):
    return Workbench(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")

# --- Test Cases ---

# Test __init__ (remain the same)
def test_workbench_init_url_fix():
    wb = Workbench(api_url="http://dummy.com", api_user="user", api_token="token")
    assert wb.api_url == "http://dummy.com/api.php"

def test_workbench_init_url_correct():
    wb = Workbench(api_url="http://dummy.com/api.php", api_user="user", api_token="token")
    assert wb.api_url == "http://dummy.com/api.php"

# --- Test _send_request ---
def test_send_request_success(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.json.return_value = {"status": "1", "data": {"key": "value"}}
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "test"}
    result = workbench_inst._send_request(payload)
    mock_session.post.assert_called_once()
    assert result == {"status": "1", "data": {"key": "value"}}

def test_send_request_api_error(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.json.return_value = {"status": "0", "error": "A generic failure"} # API error status
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "fail"}
    with pytest.raises(ApiError, match="API returned error: A generic failure"):
        workbench_inst._send_request(payload)

def test_send_request_network_error(workbench_inst, mock_session):
    mock_session.post.side_effect = requests.exceptions.ConnectionError("Failed to connect")
    payload = {"group": "test", "action": "connectfail"}
    with pytest.raises(NetworkError, match="API request failed: Failed to connect"):
        workbench_inst._send_request(payload)

def test_send_request_timeout(workbench_inst, mock_session):
    mock_session.post.side_effect = requests.exceptions.Timeout("Request timed out")
    payload = {"group": "test", "action": "timeout"}
    with pytest.raises(NetworkError, match="API request failed: Request timed out"):
        workbench_inst._send_request(payload)

def test_send_request_invalid_json_status(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.json.return_value = {"invalid": "json"} # Missing 'status' key
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "nostatus"}
    with pytest.raises(ApiError, match="Invalid response format from API.*missing 'status'"):
        workbench_inst._send_request(payload)

def test_send_request_sync_response(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'text/html'}
    mock_response.content = b"<html>Report Content</html>"
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "sync"}
    result = workbench_inst._send_request(payload)
    assert "_raw_response" in result
    assert result["_raw_response"] == mock_response

def test_send_request_http_error(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 401 # Unauthorized
    mock_response.text = "Authentication required"
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "authfail"}
    with pytest.raises(NetworkError, match="API request failed"):
        workbench_inst._send_request(payload)

def test_send_request_json_decode_error(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'} # Claims JSON
    mock_response.text = "This is not JSON"
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "This is not JSON", 0)
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "badjson"}
    with pytest.raises(ApiError, match="Invalid JSON received from API"):
        workbench_inst._send_request(payload)

# --- Test _is_status_check_supported ---
@patch.object(Workbench, '_send_request')
def test_is_status_check_supported_yes(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    assert workbench_inst._is_status_check_supported("scan1", "SCAN") is True
    mock_send.assert_called_once()

@patch.object(Workbench, '_send_request')
def test_is_status_check_supported_no_invalid_type(mock_send, workbench_inst):
    error_payload = { # Copied from original test
        "status": "0", "error": "RequestData.Base.issues_while_parsing_request",
        "data": [{"code": "RequestData.Base.field_not_valid_option", "message_parameters": {"fieldname": "type"}}]
    }
    mock_send.return_value = error_payload
    assert workbench_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES") is False
    mock_send.assert_called_once()

@patch.object(Workbench, '_send_request')
def test_is_status_check_supported_api_error(mock_send, workbench_inst):
    # Simulate a different status 0 error
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    # Should raise the underlying API error
    with pytest.raises(ApiError, match="API error during EXTRACT_ARCHIVES support check: Scan not found"):
        workbench_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES")

@patch.object(Workbench, '_send_request')
def test_is_status_check_supported_network_error(mock_send, workbench_inst):
    # Simulate a network error during the probe
    mock_send.side_effect = NetworkError("Connection failed")
    with pytest.raises(NetworkError, match="Error during EXTRACT_ARCHIVES support check: Connection failed"):
        workbench_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES")

# --- Test _wait_for_process ---
def test_wait_for_process_success(workbench_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        {"progress_state": "RUNNING"},
        {"progress_state": "RUNNING"},
        {"progress_state": "FINISHED"},
    ]
    with patch('time.sleep', return_value=None): # Mock sleep
        success = workbench_inst._wait_for_process(
            process_description="Test Process",
            check_function=mock_check_func, check_args={"arg1": "val1"},
            status_accessor=lambda data: data.get("progress_state"),
            success_values={"FINISHED"}, failure_values={"FAILED"},
            max_tries=5, wait_interval=0.01, progress_indicator=False
        )
    assert success is True
    assert mock_check_func.call_count == 3

def test_wait_for_process_timeout(workbench_inst, mocker):
    mock_check_func = mocker.MagicMock(return_value={"progress_state": "RUNNING"})
    with patch('time.sleep', return_value=None): # Mock sleep
        with pytest.raises(ProcessTimeoutError, match="Timeout waiting for Test Timeout"):
            workbench_inst._wait_for_process(
                process_description="Test Timeout",
                check_function=mock_check_func, check_args={},
                status_accessor=lambda data: data.get("progress_state"),
                success_values={"FINISHED"}, failure_values={"FAILED"},
                max_tries=3, wait_interval=0.01, progress_indicator=False
            )
    assert mock_check_func.call_count == 3

def test_wait_for_process_failure(workbench_inst, mocker):
    mock_check_func = mocker.MagicMock(return_value={"progress_state": "FAILED", "progress": 50, "error": "Disk full"})
    with patch('time.sleep', return_value=None): # Mock sleep
        with pytest.raises(ProcessError, match="The Test Failure FAILED at 50%. The error returned by Workbench was: Disk full"):
            workbench_inst._wait_for_process(
                process_description="Test Failure",
                check_function=mock_check_func, check_args={},
                status_accessor=lambda data: data.get("progress_state"),
                success_values={"FINISHED"}, failure_values={"FAILED"},
                max_tries=5, wait_interval=0.01, progress_indicator=False
            )
    assert mock_check_func.call_count == 1 # Fails on first check

def test_wait_for_process_check_fails_retries(workbench_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        NetworkError("Network glitch"), # First call fails
        {"progress_state": "RUNNING"},        # Second call succeeds
        {"progress_state": "FINISHED"},       # Third call succeeds
    ]
    with patch('time.sleep', return_value=None): # Mock sleep
        success = workbench_inst._wait_for_process(
            process_description="Test Retry",
            check_function=mock_check_func, check_args={},
            status_accessor=lambda data: data.get("progress_state"),
            success_values={"FINISHED"}, failure_values={"FAILED"},
            max_tries=5, wait_interval=0.01, progress_indicator=False
        )
    assert success is True
    assert mock_check_func.call_count == 3

def test_wait_for_process_accessor_fails(workbench_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.return_value = {"wrong_key": "FINISHED"} # Status cannot be accessed
    with patch('time.sleep', return_value=None): # Mock sleep
        # Should treat ACCESS_ERROR as non-terminal and eventually time out
        with pytest.raises(ProcessTimeoutError, match="Timeout waiting for Test Accessor.*Last Status: ACCESS_ERROR"):
            workbench_inst._wait_for_process(
                process_description="Test Accessor",
                check_function=mock_check_func, check_args={},
                status_accessor=lambda data: data["progress_state"], # This will raise KeyError
                success_values={"FINISHED"}, failure_values={"FAILED"},
                max_tries=3, wait_interval=0.01, progress_indicator=False
            )
    assert mock_check_func.call_count == 3

# --- Test upload_files ---
@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False) # Simulate file
@patch('os.path.getsize', return_value=1024) # Small file
@patch('builtins.open', new_callable=mock_open, read_data=b'file data')
@patch('requests.Session.post') # Patch post on the session instance
def test_upload_files_file_success(mock_post, mock_open_file, mock_getsize, mock_isdir, mock_exists, workbench_inst):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "1"} # Simulate success JSON
    mock_post.return_value = mock_response

    workbench_inst.upload_files("scan1", "/path/to/file.zip")

    mock_exists.assert_called_once_with("/path/to/file.zip")
    mock_isdir.assert_called_once_with("/path/to/file.zip")
    mock_getsize.assert_called_once_with("/path/to/file.zip")
    mock_open_file.assert_called_once_with("/path/to/file.zip", "rb")
    mock_post.assert_called_once()
    # Check headers passed to post
    call_args, call_kwargs = mock_post.call_args
    headers = call_kwargs.get('headers', {})
    assert "FOSSID-SCAN-CODE" in headers
    assert "FOSSID-FILE-NAME" in headers
    assert headers.get("FOSSID-UPLOAD-TYPE") is None # Not DA import

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=True) # Simulate directory
@patch('tempfile.gettempdir', return_value='/tmp')
@patch('shutil.make_archive', return_value='/tmp/dir_temp.zip') # Mock archive creation
@patch('os.path.getsize', return_value=1024) # Small archive
@patch('builtins.open', new_callable=mock_open, read_data=b'zip data')
@patch('requests.Session.post')
@patch('os.remove') # Mock cleanup
def test_upload_files_dir_success(mock_remove, mock_post, mock_open_file, mock_getsize, mock_make_archive, mock_tempdir, mock_isdir, mock_exists, workbench_inst):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "1"}
    mock_post.return_value = mock_response

    workbench_inst.upload_files("scan2", "/path/to/dir")

    mock_exists.assert_called_once_with("/path/to/dir")
    mock_isdir.assert_called_once_with("/path/to/dir")
    mock_make_archive.assert_called_once_with('/tmp/dir_temp', 'zip', root_dir='/path/to', base_dir='dir')
    mock_getsize.assert_called_once_with('/tmp/dir_temp.zip')
    mock_open_file.assert_called_once_with('/tmp/dir_temp.zip', "rb")
    mock_post.assert_called_once()
    mock_remove.assert_called_once_with('/tmp/dir_temp.zip')

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=20 * 1024 * 1024) # Large file
@patch('builtins.open', new_callable=mock_open, read_data=b'large data chunk')
@patch.object(Workbench, '_read_in_chunks', return_value=[b'chunk1', b'chunk2']) # Mock chunk reading
@patch.object(Workbench, '_chunked_upload_request') # Mock the chunk upload helper
def test_upload_files_chunked_success(mock_chunk_req, mock_read_chunks, mock_open_file, mock_getsize, mock_isdir, mock_exists, workbench_inst):
    workbench_inst.upload_files("scan3", "/path/to/largefile.bin")

    mock_exists.assert_called_once()
    mock_isdir.assert_called_once()
    mock_getsize.assert_called_once()
    mock_open_file.assert_called_once()
    mock_read_chunks.assert_called_once()
    # Check _chunked_upload_request was called for each chunk
    assert mock_chunk_req.call_count == 2
    # Check headers passed to first chunk request
    call_args, _ = mock_chunk_req.call_args_list[0]
    scan_code_arg, headers_arg, chunk_arg = call_args
    assert scan_code_arg == "scan3"
    assert headers_arg.get('Transfer-Encoding') == 'chunked'
    assert headers_arg.get('Content-Type') == 'application/octet-stream'
    assert chunk_arg == b'chunk1'

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=1024)
@patch('builtins.open', new_callable=mock_open, read_data=b'file data')
@patch('requests.Session.post')
def test_upload_files_da_import(mock_post, mock_open_file, mock_getsize, mock_isdir, mock_exists, workbench_inst):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "1"}
    mock_post.return_value = mock_response

    workbench_inst.upload_files("scan4", "/path/to/results.json", is_da_import=True)

    mock_post.assert_called_once()
    call_args, call_kwargs = mock_post.call_args
    headers = call_kwargs.get('headers', {})
    assert headers.get("FOSSID-UPLOAD-TYPE") == "dependency_analysis"

@patch('os.path.exists', return_value=False)
def test_upload_files_path_not_found(workbench_inst):
    with pytest.raises(FileSystemError, match="Path does not exist"):
        workbench_inst.upload_files("scan5", "/non/existent/path")

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=1024)
@patch('builtins.open', new_callable=mock_open, read_data=b'file data')
@patch('requests.Session.post', side_effect=NetworkError("Network Error"))
def test_upload_files_network_error(mock_post, mock_open_file, mock_getsize, mock_isdir, mock_exists, workbench_inst):
    with pytest.raises(NetworkError, match="Failed to upload.*Network Error"):
        workbench_inst.upload_files("scan6", "/path/to/file.zip")

# --- Test get_* methods ---
@patch.object(Workbench, '_send_request')
def test_get_pending_files_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"1": "/path/a", "2": "/path/b"}}
    result = workbench_inst.get_pending_files("scan1")
    assert result == {"1": "/path/a", "2": "/path/b"}
    mock_send.assert_called_once()

@patch.object(Workbench, '_send_request')
def test_get_pending_files_empty(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {}} # Empty dict
    result = workbench_inst.get_pending_files("scan1")
    assert result == {}

@patch.object(Workbench, '_send_request')
def test_get_pending_files_api_error(mock_send, workbench_inst):
    # Simulate API error (status 0) - should log and return empty dict
    mock_send.return_value = {"status": "0", "error": "Some API issue"}
    result = workbench_inst.get_pending_files("scan1")
    assert result == {} # Should not raise, just return empty

@patch.object(Workbench, '_send_request')
def test_get_scan_identified_components_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": [ # API returns a list
        {"name": "Comp A", "version": "1.0"},
        {"name": "Comp B", "version": "2.0"}
    ]}
    result = workbench_inst.get_scan_identified_components("scan1")
    assert len(result) == 2
    assert {"name": "Comp A", "version": "1.0"} in result
    assert {"name": "Comp B", "version": "2.0"} in result

@patch.object(Workbench, '_send_request', side_effect=ApiError("API failed"))
def test_get_scan_identified_components_fail(mock_send, workbench_inst):
    with pytest.raises(ApiError, match="Error retrieving identified components.*API failed"):
        workbench_inst.get_scan_identified_components("test_scan")

@patch.object(Workbench, '_send_request')
def test_get_dependency_analysis_results_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": [{"name": "Dep A", "version": "1.0"}]}
    result = workbench_inst.get_dependency_analysis_results("scan1")
    assert result == [{"name": "Dep A", "version": "1.0"}]

@patch.object(Workbench, '_send_request')
def test_get_dependency_analysis_results_not_run(mock_send, workbench_inst):
    # Simulate the specific "not run" error
    mock_send.return_value = {"status": "0", "error": "Dependency analysis has not been run"}
    result = workbench_inst.get_dependency_analysis_results("scan1")
    assert result == [] # Should return empty list, not raise

@patch.object(Workbench, '_send_request')
def test_get_dependency_analysis_results_other_error(mock_send, workbench_inst):
    # Simulate a different status 0 error
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    # Should raise exception
    with pytest.raises(ApiError, match="Error getting dependency analysis results.*Scan not found"):
        workbench_inst.get_dependency_analysis_results("scan1")

# --- Test create_project / create_webapp_scan ---
@patch.object(Workbench, '_send_request')
def test_create_project_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"project_code": "NEW_PROJ"}}
    result = workbench_inst.create_project("New Project")
    assert result == "NEW_PROJ"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['action'] == 'create'
    assert payload['data']['project_name'] == 'New Project'

@patch.object(Workbench, '_send_request')
@patch.object(Workbench, 'list_projects') # Mock list_projects for the fallback
def test_create_project_already_exists(mock_list_proj, mock_send, workbench_inst):
    # First call to _send_request simulates "already exists"
    # Note: The actual API might return status 0, error: Project code already exists
    mock_send.return_value = {"status": "0", "error": "Project code already exists: EXISTING_PROJ"}
    # Second call (list_projects) finds the existing project
    mock_list_proj.return_value = [{"name": "New Project", "code": "EXISTING_PROJ"}]

    # Expect ProjectExistsError to be caught and handled internally
    result = workbench_inst.create_project("New Project")
    assert result == "EXISTING_PROJ"
    assert mock_send.call_count == 1 # Only create is attempted
    mock_list_proj.assert_called_once_with(project_name="New Project") # Fallback lookup is done

@patch.object(Workbench, '_send_request')
def test_create_webapp_scan_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    # create_webapp_scan returns True on success, not the ID
    result = workbench_inst.create_webapp_scan("New Scan", "PROJ1")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['action'] == 'create'
    assert payload['data']['scan_name'] == 'New Scan'
    assert payload['data']['project_code'] == 'PROJ1'

@patch.object(Workbench, '_send_request', return_value={"status": "0", "error": "Scan code already exists: EXISTING_SCAN"})
def test_create_webapp_scan_already_exists(mock_send, workbench_inst):
    # Expect ScanExistsError to be raised
    with pytest.raises(ScanExistsError, match="Scan code already exists: EXISTING_SCAN"):
        workbench_inst.create_webapp_scan("Existing Scan", "PROJ1")