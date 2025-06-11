# tests/api/test_workbench_api_helpers.py

import pytest
import requests
import json
import time
from unittest.mock import MagicMock, patch, mock_open
import os
import tempfile
import shutil
import zipfile
from pathlib import Path

from workbench_cli.api.workbench_api_helpers import WorkbenchAPIHelpers
from workbench_cli.utilities.prep_upload_archive import UploadArchivePrep
from workbench_cli.exceptions import (
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
    ScanNotFoundError
)

# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch('requests.Session', return_value=mock_sess)
    return mock_sess

@pytest.fixture
def helpers_inst(mock_session):
    """Create a WorkbenchAPIHelpers instance with a properly mocked session."""
    # Create a new instance
    helpers = WorkbenchAPIHelpers(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")
    # Replace the session with our mock
    helpers.session = mock_session
    return helpers

# --- Test Helper init ---
def test_helpers_init_url_fix():
    helpers = WorkbenchAPIHelpers(api_url="http://dummy.com", api_user="user", api_token="token")
    assert helpers.api_url == "http://dummy.com/api.php"

def test_helpers_init_url_correct():
    helpers = WorkbenchAPIHelpers(api_url="http://dummy.com/api.php", api_user="user", api_token="token")
    assert helpers.api_url == "http://dummy.com/api.php"

# --- Test _send_request ---
def test_send_request_success(helpers_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.json.return_value = {"status": "1", "data": {"key": "value"}}
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "test"}
    result = helpers_inst._send_request(payload)
    mock_session.post.assert_called_once()
    assert result == {"status": "1", "data": {"key": "value"}}

def test_send_request_api_error(helpers_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.json.return_value = {"status": "0", "error": "A generic failure"} # API error status
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "fail"}
    with pytest.raises(ApiError, match="A generic failure"):
        helpers_inst._send_request(payload)

def test_send_request_network_error(helpers_inst, mock_session):
    mock_session.post.side_effect = requests.exceptions.ConnectionError("Failed to connect")
    payload = {"group": "test", "action": "connectfail"}
    with pytest.raises(NetworkError, match="Failed to connect to the API server"):
        helpers_inst._send_request(payload)

def test_send_request_timeout(helpers_inst, mock_session):
    mock_session.post.side_effect = requests.exceptions.Timeout("Request timed out")
    payload = {"group": "test", "action": "timeout"}
    with pytest.raises(NetworkError, match="Request to API server timed out"):
        helpers_inst._send_request(payload)

def test_send_request_json_decode_error(helpers_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'} # Claims JSON
    mock_response.text = "This is not JSON"
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "This is not JSON", 0)
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "badjson"}
    with pytest.raises(ApiError, match="Invalid JSON received from API"):
        helpers_inst._send_request(payload)

def test_send_request_sync_response(helpers_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'text/html'}
    mock_response.content = b"<html>Report Content</html>"
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "sync"}
    result = helpers_inst._send_request(payload)
    assert "_raw_response" in result
    assert result["_raw_response"] == mock_response

def test_send_request_http_error(helpers_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 401  # Unauthorized
    mock_response.headers = {}  # Add this line to avoid AttributeError
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Client Error", response=mock_response)
    mock_session.post.return_value = mock_response
    
    payload = {"group": "test", "action": "authfail"}
    try:
        helpers_inst._send_request(payload)
        pytest.fail("Expected AuthenticationError to be raised")
    except AuthenticationError as e:
        # This will pass if the exception is raised with the correct type
        assert "Invalid credentials or expired token" in str(e)

def test_send_request_git_repository_access_error(helpers_inst, mock_session):
    """Test detection of Git repository access errors."""
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.json.return_value = {
        "status": "0", 
        "error": "RequestData.Base.issues_while_parsing_request",
        "data": [{
            "code": "RequestData.Base.issue_with_executing_command",
            "message": "Field git_repo_url: there was an issue executing command: timeout 200 git ls-remote 'https://github.com/fake/repo' 2>&1.",
            "message_parameters": {
                "fieldname": "git_repo_url",
                "cmd": "timeout 200 git ls-remote 'https://github.com/fake/repo' 2>&1",
                "exitStatus": 128,
                "out": "fatal: could not read Username for 'https://github.com': No such device or address"
            }
        }]
    }
    mock_session.post.return_value = mock_response
    
    payload = {"group": "scans", "action": "create", "data": {"git_repo_url": "https://github.com/fake/repo"}}
    
    with pytest.raises(ApiError) as exc_info:
        helpers_inst._send_request(payload)
    
    assert "Git repository access error" in str(exc_info.value)
    assert "code" in exc_info.value.__dict__
    assert exc_info.value.__dict__["code"] == "git_repository_access_error"

# --- Test _is_status_check_supported ---
def test_is_status_check_supported_yes(helpers_inst):
    with patch.object(helpers_inst, '_send_request', return_value={"status": "1"}):
        assert helpers_inst._is_status_check_supported("scan1", "SCAN") is True

def test_is_status_check_supported_no_invalid_type(helpers_inst):
    error_payload = {
        "status": "0", "error": "RequestData.Base.issues_while_parsing_request",
        "data": [{"code": "RequestData.Base.field_not_valid_option", "message_parameters": {"fieldname": "type"}}]
    }
    with patch.object(helpers_inst, '_send_request', return_value=error_payload):
        assert helpers_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES") is False

def test_is_status_check_supported_api_error(helpers_inst):
    with patch.object(helpers_inst, '_send_request', return_value={"status": "0", "error": "Scan not found"}):
        with pytest.raises(ApiError, match="API error during EXTRACT_ARCHIVES support check: Scan not found"):
            helpers_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES")

def test_is_status_check_supported_network_error(helpers_inst):
    with patch.object(helpers_inst, '_send_request', side_effect=NetworkError("Connection failed")):
        with pytest.raises(NetworkError):
            helpers_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES")

# --- Test _wait_for_process ---
def test_wait_for_process_success(helpers_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        {"progress_state": "RUNNING"},
        {"progress_state": "RUNNING"},
        {"progress_state": "FINISHED"},
    ]
    with patch('time.sleep', return_value=None): # Mock sleep
        success = helpers_inst._wait_for_process(
            process_description="Test Process",
            check_function=mock_check_func, check_args={"arg1": "val1"},
            status_accessor=lambda data: data.get("progress_state"),
            success_values={"FINISHED"}, failure_values={"FAILED"},
            max_tries=5, wait_interval=0.01, progress_indicator=False
        )
    assert success is True
    assert mock_check_func.call_count == 3

def test_wait_for_process_timeout(helpers_inst, mocker):
    mock_check_func = mocker.MagicMock(return_value={"progress_state": "RUNNING"})
    with patch('time.sleep', return_value=None): # Mock sleep
        with pytest.raises(ProcessTimeoutError, match="Timeout waiting for Test Timeout"):
            helpers_inst._wait_for_process(
                process_description="Test Timeout",
                check_function=mock_check_func, check_args={},
                status_accessor=lambda data: data.get("progress_state"),
                success_values={"FINISHED"}, failure_values={"FAILED"},
                max_tries=3, wait_interval=0.01, progress_indicator=False
            )
    assert mock_check_func.call_count == 3

def test_wait_for_process_failure(helpers_inst, mocker):
    mock_check_func = mocker.MagicMock(return_value={"progress_state": "FAILED", "error": "Disk full"})
    with patch('time.sleep', return_value=None): # Mock sleep
        with pytest.raises(ProcessError, match="The Test Failure FAILED"):
            helpers_inst._wait_for_process(
                process_description="Test Failure",
                check_function=mock_check_func, check_args={},
                status_accessor=lambda data: data.get("progress_state"),
                success_values={"FINISHED"}, failure_values={"FAILED"},
                max_tries=5, wait_interval=0.01, progress_indicator=False
            )
    assert mock_check_func.call_count == 1 # Fails on first check

def test_wait_for_process_check_fails_retries(helpers_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        NetworkError("Network glitch"), # First call fails
        {"progress_state": "RUNNING"},        # Second call succeeds
        {"progress_state": "FINISHED"},       # Third call succeeds
    ]
    with patch('time.sleep', return_value=None): # Mock sleep
        success = helpers_inst._wait_for_process(
            process_description="Test Retry",
            check_function=mock_check_func, check_args={},
            status_accessor=lambda data: data.get("progress_state"),
            success_values={"FINISHED"}, failure_values={"FAILED"},
            max_tries=5, wait_interval=0.01, progress_indicator=False
        )
    assert success is True
    assert mock_check_func.call_count == 3

def test_wait_for_process_accessor_fails(helpers_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.return_value = {"wrong_key": "FINISHED"} # Status cannot be accessed
    with patch('time.sleep', return_value=None): # Mock sleep
        try:
            helpers_inst._wait_for_process(
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

# --- Test standard_scan_status_accessor ---
def test_standard_scan_status_accessor_with_is_finished(helpers_inst):
    data = {"is_finished": "1"}
    status = helpers_inst._standard_scan_status_accessor(data)
    assert status == "FINISHED"
    
    data = {"is_finished": True}
    status = helpers_inst._standard_scan_status_accessor(data)
    assert status == "FINISHED"

def test_standard_scan_status_accessor_with_status(helpers_inst):
    data = {"status": "RUNNING"}
    status = helpers_inst._standard_scan_status_accessor(data)
    assert status == "RUNNING"
    
    data = {"status": "running"}  # Lowercase
    status = helpers_inst._standard_scan_status_accessor(data)
    assert status == "RUNNING"  # Should be uppercase

def test_standard_scan_status_accessor_unknown(helpers_inst):
    data = {"some_other_key": "value"}
    status = helpers_inst._standard_scan_status_accessor(data)
    assert status == "UNKNOWN"

def test_standard_scan_status_accessor_access_error(helpers_inst):
    data = 123  # Not a dict, will cause AttributeError
    status = helpers_inst._standard_scan_status_accessor(data)
    assert status == "ACCESS_ERROR"

# --- Test assert_process_can_start ---
def test_assert_process_can_start_when_new(helpers_inst, mocker):
    # Since WorkbenchAPIHelpers doesn't directly have get_scan_status (it's in the WorkbenchAPI class),
    # we need to add it for testing purposes
    helpers_inst.get_scan_status = mocker.MagicMock(return_value={"status": "NEW"})
    
    # Should not raise exception
    helpers_inst.assert_process_can_start("SCAN", "scan1", 30, 5)
    helpers_inst.get_scan_status.assert_called_once_with("SCAN", "scan1")

def test_assert_process_can_start_when_finished(helpers_inst, mocker):
    # Mock the get_scan_status method for testing
    helpers_inst.get_scan_status = mocker.MagicMock(return_value={"status": "FINISHED"})
    
    # Should not raise exception
    helpers_inst.assert_process_can_start("SCAN", "scan1", 30, 5)
    helpers_inst.get_scan_status.assert_called_once_with("SCAN", "scan1")

def test_assert_process_can_start_when_failed(helpers_inst, mocker):
    # Mock the get_scan_status method for testing
    helpers_inst.get_scan_status = mocker.MagicMock(return_value={"status": "FAILED"})
    
    # Should not raise exception
    helpers_inst.assert_process_can_start("SCAN", "scan1", 30, 5)
    helpers_inst.get_scan_status.assert_called_once_with("SCAN", "scan1")

def test_assert_process_can_start_when_running_then_wait_success(helpers_inst, mocker):
    # Mock required methods
    helpers_inst.get_scan_status = mocker.MagicMock(return_value={"status": "RUNNING"})
    helpers_inst.wait_for_scan_to_finish = mocker.MagicMock(return_value=({"status": "FINISHED"}, 10.0))
    
    # This should complete without error
    helpers_inst.assert_process_can_start("SCAN", "scan1", 30, 5)
    
    # Verify both methods were called as expected
    helpers_inst.get_scan_status.assert_called_once_with("SCAN", "scan1")
    helpers_inst.wait_for_scan_to_finish.assert_called_once_with("SCAN", "scan1", 30, 5)

def test_assert_process_can_start_when_running_then_wait_error(helpers_inst, mocker):
    # Mock required methods
    helpers_inst.get_scan_status = mocker.MagicMock(return_value={"status": "RUNNING"})
    helpers_inst.wait_for_scan_to_finish = mocker.MagicMock(side_effect=ProcessTimeoutError("Wait timeout"))
    
    with pytest.raises(ProcessError):
        helpers_inst.assert_process_can_start("SCAN", "scan1", 30, 5)
    
    # Verify both methods were called as expected
    helpers_inst.get_scan_status.assert_called_once_with("SCAN", "scan1")
    helpers_inst.wait_for_scan_to_finish.assert_called_once_with("SCAN", "scan1", 30, 5)

def test_assert_process_can_start_other_status(helpers_inst, mocker):
    """Test assert_process_can_start with a status that isn't allowed."""
    
    # Add the get_scan_status mock method to the helpers instance
    helpers_inst.get_scan_status = mocker.MagicMock(return_value={"status": "RUNNING"})
    
    # Mock wait_for_scan_to_finish to fail with a timeout
    helpers_inst.wait_for_scan_to_finish = mocker.MagicMock(
        side_effect=ProcessTimeoutError("SCAN timed out for scan 'scan1' after 1 attempts")
    )
    
    # The helper's assert_process_can_start method should raise a ProcessError
    with pytest.raises(ProcessError, match="Could not verify if scan can start for 'scan1'"):
        helpers_inst.assert_process_can_start("SCAN", "scan1", 1, 1)

def test_assert_process_can_start_scan_not_found(helpers_inst, mocker):
    # Mock the get_scan_status method to raise ScanNotFoundError
    helpers_inst.get_scan_status = mocker.MagicMock(side_effect=ScanNotFoundError("Scan not found"))
    
    # Should propagate the ScanNotFoundError
    with pytest.raises(ScanNotFoundError, match="Scan not found"):
        helpers_inst.assert_process_can_start("SCAN", "scan1", 30, 5)

def test_assert_process_can_start_invalid_type(helpers_inst):
    # Should raise ValueError for invalid process type
    with pytest.raises(ValueError, match="Invalid process_type 'INVALID' provided to assert_process_can_start"):
        helpers_inst.assert_process_can_start("INVALID", "scan1", 30, 5)

# --- Tests for gitignore handling ---
def test_parse_gitignore_file_exists(helpers_inst, mocker):
    """Test parsing a .gitignore file when the file exists."""
    # Setup explicit mock content
    mock_content = "node_modules/\n*.log\n# Comment\ntemp/\n"
    expected_patterns = ["node_modules/", "*.log", "temp/"]
    
    # Setup mock for open function with more robust error handling
    mock_open_func = mocker.mock_open(read_data=mock_content)
    
    # Apply mocks with safer approach that works in both pytest-mock and our fallback
    open_patch = mocker.patch("builtins.open", mock_open_func)
    isfile_patch = mocker.patch("os.path.exists", return_value=True)
    
    try:
        # Ensure mocks are applied
        assert open_patch is not None, "Failed to mock 'open' function"
        assert isfile_patch is not None, "Failed to mock 'os.path.isfile' function"
        
        # Get gitignore patterns - now using UploadArchivePrep static method
        patterns = UploadArchivePrep._parse_gitignore("/fake/path")
        
        # More detailed assertions with diagnostic output
        if len(patterns) != len(expected_patterns):
            print(f"ERROR: Expected {len(expected_patterns)} patterns but got {len(patterns)}")
            print(f"Mock content lines: {mock_content.splitlines()}")
            print(f"Parsed patterns: {patterns}")
            print(f"Expected patterns: {expected_patterns}")
        
        # Should have 3 patterns (comment line is excluded)
        assert len(patterns) == len(expected_patterns), f"Expected {len(expected_patterns)} patterns but got {len(patterns)}: {patterns}"
        
        # Check each pattern explicitly
        for pattern in expected_patterns:
            assert pattern in patterns, f"Pattern '{pattern}' missing from parsed patterns: {patterns}"
    
    except Exception as e:
        print(f"Exception in test_parse_gitignore_file_exists: {str(e)}")
        print(f"Mock content: {mock_content}")
        print(f"Open mock called: {mock_open_func.called}")
        print(f"Isfile mock called: {isfile_patch.called if hasattr(isfile_patch, 'called') else 'Unknown'}")
        raise

def test_parse_gitignore_file_not_exists(helpers_inst, mocker):
    # Mock os.path.exists to return False
    mocker.patch("os.path.exists", return_value=False)
    
    patterns = UploadArchivePrep._parse_gitignore("/fake/path")
    
    # Should return empty list
    assert patterns == []

def test_is_excluded_by_gitignore_exact_match(helpers_inst):
    patterns = ["node_modules/", "*.log", "build/"]
    
    # Test exact matches
    assert UploadArchivePrep._is_excluded_by_gitignore("node_modules", patterns, is_dir=True)
    assert UploadArchivePrep._is_excluded_by_gitignore("build", patterns, is_dir=True)
    
    # Test file match
    assert UploadArchivePrep._is_excluded_by_gitignore("error.log", patterns) is True
    assert UploadArchivePrep._is_excluded_by_gitignore("logs/debug.log", patterns) is True
    
    # Test non-match
    assert UploadArchivePrep._is_excluded_by_gitignore("src/app.js", patterns) is False
    assert UploadArchivePrep._is_excluded_by_gitignore("package.json", patterns) is False

def test_is_excluded_by_gitignore_empty_patterns(helpers_inst):
    # Should return False for any path if patterns is empty
    assert UploadArchivePrep._is_excluded_by_gitignore("node_modules", []) is False
    assert UploadArchivePrep._is_excluded_by_gitignore("any/path", []) is False

# --- Tests for file operations ---
def test_create_zip_archive(helpers_inst, mocker):
    """Test creating a ZIP archive from a directory structure."""
    # Create a temporary directory structure for testing
    temp_dir = None
    zip_path = None
    extract_dir = None
    
    try:
        # Use context manager for temporary directory to ensure cleanup
        with tempfile.TemporaryDirectory() as temp_str:
            temp_dir = Path(temp_str)
            
            # Create directory structure with more robust path handling
            (temp_dir / "src").mkdir()
            (temp_dir / "docs").mkdir()
            (temp_dir / ".git").mkdir()  # Should be excluded
            (temp_dir / "__pycache__").mkdir()  # Should be excluded
            
            # Create some files with more robust path handling
            (temp_dir / "src" / "main.py").write_text("print('Hello, world!')")
            (temp_dir / "docs" / "readme.md").write_text("# Test Project")
            (temp_dir / ".git" / "config").write_text("# Git config")
            (temp_dir / ".gitignore").write_text("*.log\nbuild/\n")
            
            # Create a file that should be excluded by gitignore
            (temp_dir / "debug.log").write_text("DEBUG LOG")
            (temp_dir / "build").mkdir()
            (temp_dir / "build" / "output.txt").write_text("Build output")

            # Add debug output for CI troubleshooting
            print(f"Debug - Created test directory structure at: {temp_dir}")
            print(f"Debug - Directory contents: {list(temp_dir.glob('**/*'))}")
            
            # Call the method to create a zip archive - capture any exceptions for better diagnostics
            try:
                zip_path = UploadArchivePrep.create_zip_archive(str(temp_dir))
                print(f"Debug - Created ZIP archive at: {zip_path}")
            except Exception as e:
                print(f"Debug - Error creating ZIP: {str(e)}")
                raise
                
            # Verify the zip file was created
            assert os.path.exists(zip_path), f"ZIP file was not created at {zip_path}"
            
            # Extract the contents to a new temp directory for verification
            with tempfile.TemporaryDirectory() as extract_str:
                extract_dir = Path(extract_str)
                
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        # Print ZIP contents for debugging
                        print(f"Debug - ZIP archive contents: {zip_ref.namelist()}")
                        zip_ref.extractall(extract_dir)
                except Exception as e:
                    print(f"Debug - Error extracting ZIP: {str(e)}")
                    raise
                    
                # Get list of all extracted files - normalize paths for cross-platform compatibility
                extracted_files = []
                for root, _, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, extract_dir)
                        # Normalize path for cross-platform comparison
                        norm_path = rel_path.replace(os.sep, '/')
                        extracted_files.append(norm_path)
                
                print(f"Debug - Extracted files: {extracted_files}")
                
                # Check included files - archives contain relative paths from source directory
                included_files = [
                    "src/main.py",
                    "docs/readme.md",
                    ".gitignore"  # .gitignore should be included
                ]
                for file_path in included_files:
                    norm_path = file_path.replace('/', os.sep)
                    assert norm_path in extracted_files or file_path in extracted_files, \
                        f"Expected file {file_path} not found in ZIP contents: {extracted_files}"
                
                # Check excluded files/directories (by .gitignore)
                excluded_gitignore = [
                    "debug.log",          # *.log pattern
                    "build/output.txt",   # build/ pattern
                ]
                for file_path in excluded_gitignore:
                    norm_path = file_path.replace('/', os.sep)
                    assert norm_path not in extracted_files and file_path not in extracted_files, \
                        f"Gitignore-excluded file {file_path} found in ZIP contents: {extracted_files}"
                
                # Check excluded directories (always excluded)
                excluded_dirs = [".git", "__pycache__"]
                for dir_name in excluded_dirs:
                    prefix = f"{dir_name}/"
                    has_excluded = any(f.startswith(prefix) or f.startswith(prefix.replace('/', os.sep)) 
                                     for f in extracted_files)
                    assert not has_excluded, \
                        f"Always-excluded directory content from {dir_name} found in ZIP: {extracted_files}"
                    
    except Exception as e:
        print(f"Test failed with error: {str(e)}")
        # Print additional debug information
        if temp_dir and os.path.exists(str(temp_dir)):
            print(f"Temp directory exists: {temp_dir}")
        if zip_path and os.path.exists(zip_path):
            print(f"ZIP file exists: {zip_path}")
        if extract_dir and os.path.exists(str(extract_dir)):
            print(f"Extract directory exists: {extract_dir}")
        raise
    
    finally:
        # Ensure cleanup happens even if assertions fail
        # Note: Using context managers above should handle most cleanup,
        # but this is a backup for the zip file which may be in a separate location
        if zip_path and os.path.exists(zip_path):
            try:
                parent_dir = os.path.dirname(zip_path)
                if os.path.exists(parent_dir):
                    shutil.rmtree(parent_dir, ignore_errors=True)
            except Exception as e:
                print(f"Warning: Cleanup failed for {parent_dir}: {str(e)}")
