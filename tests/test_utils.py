import pytest
import argparse # Added for mock_params in moved tests
import time # Added for time.sleep mock in moved tests
from unittest.mock import MagicMock, patch

from workbench_agent.utils import (
    _resolve_project,
    _resolve_scan,
    _execute_standard_scan_flow,
    fetch_and_process_results,
    _save_report_content,
    _ensure_scan_compatibility # Import added
)
from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError, # Import added
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError, # Import added
    ScanExistsError # Import added
)
# Import Workbench needed for type hinting/mocking in moved tests
from workbench_agent.api import Workbench

@pytest.fixture
def mock_workbench(mocker): # Use mocker fixture for MagicMock
    workbench = mocker.MagicMock(spec=Workbench) # Use spec for better mocking
    workbench.list_projects.return_value = [
        {"name": "test_project", "code": "TEST_PROJECT"}
    ]
    # Simulate get_project_scans which is often used by _resolve_scan
    workbench.get_project_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    # Simulate list_scans (global) if needed, though get_project_scans is preferred
    workbench.list_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    return workbench

@pytest.fixture
def mock_params(mocker): # Use mocker fixture for MagicMock
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    # Add defaults needed by moved tests
    params.command = None
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.git_depth = None
    return params

# --- Tests for _resolve_project ---
def test_resolve_project_success(mock_workbench):
    result = _resolve_project(mock_workbench, "test_project")
    assert result == "TEST_PROJECT"
    mock_workbench.list_projects.assert_called_once_with(project_name="test_project")

def test_resolve_project_not_found_no_create(mock_workbench):
    mock_workbench.list_projects.return_value = [] # Simulate not found
    with pytest.raises(ProjectNotFoundError) as exc_info:
        _resolve_project(mock_workbench, "nonexistent_project", create_if_missing=False)
    assert "Project 'nonexistent_project' not found" in str(exc_info.value)

@patch('workbench_agent.utils._resolve_project', return_value="EXISTING_PROJ") # Mock recursive call if needed
def test_resolve_project_found_create_raises(mock_recursive_resolve, mock_workbench):
    # If create_if_missing is True but project is found by list_projects
    with pytest.raises(ProjectExistsError) as exc_info:
         _resolve_project(mock_workbench, "test_project", create_if_missing=True)
    assert "Project 'test_project' already exists" in str(exc_info.value)
    # Ensure create_project was NOT called
    mock_workbench.create_project.assert_not_called()

@patch('workbench_agent.utils._resolve_project') # Patch recursive call
def test_resolve_project_create_success(mock_recursive_resolve, mock_workbench):
    # First list_projects finds nothing
    # Second list_projects (after create) finds the new one
    mock_workbench.list_projects.side_effect = [
        [], # Not found initially
        [{"name": "NewProject", "code": "NEW_CODE"}] # Found after create
    ]
    mock_workbench.create_project.return_value = "NEW_CODE" # Simulate create returning code

    # Mock the recursive call to return the final code directly after creation
    mock_recursive_resolve.return_value = "NEW_CODE"

    result = _resolve_project(mock_workbench, "NewProject", create_if_missing=True)

    assert result == "NEW_CODE"
    assert mock_workbench.list_projects.call_count == 1 # Only initial list call
    mock_workbench.create_project.assert_called_once_with("NewProject")
    # The recursive call happens *after* create_project
    mock_recursive_resolve.assert_called_once_with(mock_workbench, "NewProject", create_if_missing=False)


def test_resolve_project_api_error(mock_workbench):
    mock_workbench.list_projects.side_effect = ApiError("API error")
    with pytest.raises(ApiError) as exc_info:
        _resolve_project(mock_workbench, "test_project")
    # Check if the error message is wrapped/enhanced
    assert "Failed to resolve project 'test_project'" in str(exc_info.value)
    assert "API error" in str(exc_info.value)


def test_resolve_project_network_error(mock_workbench):
    mock_workbench.list_projects.side_effect = NetworkError("Network error")
    with pytest.raises(NetworkError) as exc_info:
        _resolve_project(mock_workbench, "test_project")
    assert "Network error while resolving project 'test_project'" in str(exc_info.value)
    assert "Network error" in str(exc_info.value)


# --- Tests for _resolve_scan ---
def test_resolve_scan_success_project_scope(mock_workbench, mock_params):
    result = _resolve_scan(mock_workbench, "test_scan", "test_project", params=mock_params)
    assert result == ("TEST_SCAN", "123")
    mock_workbench.get_project_scans.assert_called_once_with("TEST_PROJECT", scan_name="test_scan")
    mock_workbench.list_scans.assert_not_called() # Should use project scope

def test_resolve_scan_success_global_scope(mock_workbench, mock_params):
    # Simulate finding in global list
    mock_workbench.list_scans.return_value = [{"name": "global_scan", "code": "GLOBAL_SCAN", "id": "456"}]
    result = _resolve_scan(mock_workbench, "global_scan", project_name=None, params=mock_params)
    assert result == ("GLOBAL_SCAN", "456")
    mock_workbench.list_scans.assert_called_once_with(scan_name="global_scan")
    mock_workbench.get_project_scans.assert_not_called()

def test_resolve_scan_not_found_project_scope(mock_workbench, mock_params):
    mock_workbench.get_project_scans.return_value = [] # Simulate not found
    with pytest.raises(ScanNotFoundError) as exc_info:
        _resolve_scan(mock_workbench, "nonexistent_scan", "test_project", params=mock_params)
    assert "Scan 'nonexistent_scan' not found in project 'test_project'" in str(exc_info.value)

def test_resolve_scan_not_found_global_scope(mock_workbench, mock_params):
    mock_workbench.list_scans.return_value = [] # Simulate not found
    with pytest.raises(ScanNotFoundError) as exc_info:
        _resolve_scan(mock_workbench, "nonexistent_scan", project_name=None, params=mock_params)
    assert "Scan 'nonexistent_scan' not found" in str(exc_info.value) # No project context

@patch('workbench_agent.utils._ensure_scan_compatibility') # Mock compatibility check
def test_resolve_scan_found_create_raises_project_scope(mock_compat_check, mock_workbench, mock_params):
    # If create_if_missing is True but scan is found by get_project_scans
    mock_params.command = 'scan' # A command where create_if_missing might be True
    with pytest.raises(ScanExistsError) as exc_info:
         _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=True, params=mock_params)
    assert "Scan 'test_scan' already exists in project 'test_project'" in str(exc_info.value)
    # Ensure create_webapp_scan was NOT called
    mock_workbench.create_webapp_scan.assert_not_called()
    # Ensure compatibility check was still called
    mock_compat_check.assert_called_once()

def test_resolve_scan_api_error_project_scope(mock_workbench, mock_params):
    mock_workbench.get_project_scans.side_effect = ApiError("API error")
    with pytest.raises(ApiError) as exc_info:
        _resolve_scan(mock_workbench, "test_scan", "test_project", params=mock_params)
    assert "Failed to resolve scan 'test_scan' in project 'test_project'" in str(exc_info.value)
    assert "API error" in str(exc_info.value)

def test_resolve_scan_network_error_project_scope(mock_workbench, mock_params):
    mock_workbench.get_project_scans.side_effect = NetworkError("Network error")
    with pytest.raises(NetworkError) as exc_info:
        _resolve_scan(mock_workbench, "test_scan", "test_project", params=mock_params)
    assert "Network error while resolving scan 'test_scan' in project 'test_project'" in str(exc_info.value)
    assert "Network error" in str(exc_info.value)

# --- Tests for _execute_standard_scan_flow ---
@patch("workbench_agent.utils.fetch_and_process_results")
def test_execute_standard_scan_flow_success(mock_fetch_results, mock_workbench, mock_params):
    # Assume start_scan and wait_for_scan_to_finish succeed via mock_workbench
    _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")

    mock_workbench.start_scan.assert_called_once_with("TEST_SCAN")
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with(
        "SCAN", "TEST_SCAN", mock_params.scan_number_of_tries, mock_params.scan_wait_time
    )
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")

def test_execute_standard_scan_flow_start_api_error(mock_workbench, mock_params):
    mock_workbench.start_scan.side_effect = ApiError("API error on start")
    with pytest.raises(ApiError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Failed to execute standard scan flow" in str(exc_info.value)
    assert "API error on start" in str(exc_info.value)
    mock_workbench.wait_for_scan_to_finish.assert_not_called() # Should fail before waiting

def test_execute_standard_scan_flow_wait_network_error(mock_workbench, mock_params):
    mock_workbench.wait_for_scan_to_finish.side_effect = NetworkError("Network error on wait")
    with pytest.raises(NetworkError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Network error during standard scan flow" in str(exc_info.value)
    assert "Network error on wait" in str(exc_info.value)
    mock_workbench.start_scan.assert_called_once() # Start should have been called

def test_execute_standard_scan_flow_wait_process_error(mock_workbench, mock_params):
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessError("Process error on wait")
    with pytest.raises(ProcessError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Process error during standard scan flow" in str(exc_info.value)
    assert "Process error on wait" in str(exc_info.value)

def test_execute_standard_scan_flow_wait_process_timeout(mock_workbench, mock_params):
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Process timeout on wait")
    with pytest.raises(ProcessTimeoutError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Process timeout during standard scan flow" in str(exc_info.value)
    assert "Process timeout on wait" in str(exc_info.value)

@patch("workbench_agent.utils.fetch_and_process_results", side_effect=ApiError("API error on fetch"))
def test_execute_standard_scan_flow_fetch_error(mock_fetch_results, mock_workbench, mock_params):
    # Assume start and wait succeed
    with pytest.raises(ApiError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Failed to execute standard scan flow" in str(exc_info.value) # Check wrapping
    assert "API error on fetch" in str(exc_info.value)
    mock_workbench.start_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()
    mock_fetch_results.assert_called_once()


# --- Tests for fetch_and_process_results ---
def test_fetch_and_process_results_success_finished(mock_workbench, mock_params):
    mock_workbench.get_scan_status.return_value = {"status": "1", "data": {"status": "FINISHED"}}
    # No exception should be raised
    fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    mock_workbench.get_scan_status.assert_called_once_with("TEST_SCAN")
    # Add assertions for logging if implemented

def test_fetch_and_process_results_failed(mock_workbench, mock_params):
    mock_workbench.get_scan_status.return_value = {"status": "1", "data": {"status": "FAILED", "error_message": "Disk full"}}
    with pytest.raises(ProcessError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Scan failed. Error from Workbench: Disk full" in str(exc_info.value)

def test_fetch_and_process_results_cancelled(mock_workbench, mock_params):
    mock_workbench.get_scan_status.return_value = {"status": "1", "data": {"status": "CANCELLED"}}
    with pytest.raises(ProcessError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Scan was cancelled." in str(exc_info.value)

def test_fetch_and_process_results_unexpected_status(mock_workbench, mock_params):
    mock_workbench.get_scan_status.return_value = {"status": "1", "data": {"status": "UNKNOWN"}}
    with pytest.raises(ProcessError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Unexpected scan status received: UNKNOWN" in str(exc_info.value)

def test_fetch_and_process_results_api_error(mock_workbench, mock_params):
    mock_workbench.get_scan_status.side_effect = ApiError("API error")
    with pytest.raises(ApiError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Failed to fetch and process results" in str(exc_info.value)
    assert "API error" in str(exc_info.value)

def test_fetch_and_process_results_network_error(mock_workbench, mock_params):
    mock_workbench.get_scan_status.side_effect = NetworkError("Network error")
    with pytest.raises(NetworkError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Network error while fetching and processing results" in str(exc_info.value)
    assert "Network error" in str(exc_info.value)

# --- Tests for _save_report_content ---
def test_save_report_content_success(mock_workbench): # mock_workbench not strictly needed, but consistent
    response = MagicMock()
    response.content = b"test content"
    response.headers = {'content-type': 'text/plain'} # Example header

    with patch("builtins.open", MagicMock()) as mock_open:
        # Use specific names and types for clarity
        _save_report_content(response, "/save/path", "scan", "MyScan", "txt")
        # Assert file path construction
        expected_path = "/save/path/MyScan_scan_report.txt"
        mock_open.assert_called_once_with(expected_path, "wb")
        mock_open().write.assert_called_once_with(b"test content")

def test_save_report_content_file_system_error(mock_workbench):
    response = MagicMock()
    response.content = b"test content"
    response.headers = {'content-type': 'application/pdf'}

    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.side_effect = IOError("Permission denied") # Simulate write error
        with pytest.raises(FileSystemError) as exc_info:
            _save_report_content(response, "/locked/dir", "project", "MyProj", "pdf")
        assert "Failed to save report 'pdf' to /locked/dir/MyProj_project_report.pdf" in str(exc_info.value)
        assert "Permission denied" in str(exc_info.value)

# --- MOVED TESTS for _resolve_scan (More Cases) ---
@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
@patch('workbench_agent.utils.Workbench.create_webapp_scan')
@patch('time.sleep', return_value=None) # Mock time.sleep
def test_resolve_scan_project_scope_create_success(mock_sleep, mock_create_scan, mock_get_scans, mock_resolve_proj, mock_workbench, mock_params):
    mock_resolve_proj.return_value = "PROJ_Y"
    # First call to get_project_scans finds nothing
    # Second call after creation finds the new scan
    mock_get_scans.side_effect = [
        [], # Scan not found initially
        [{"name": "NewScan", "code": "NEW_SCAN_CODE", "id": 555}] # Found after creation
    ]
    mock_create_scan.return_value = True # Simulate successful trigger

    mock_params.command = 'scan' # A command where create_if_missing is True

    code, scan_id = _resolve_scan(
        mock_workbench, # Use mock_workbench fixture
        scan_name="NewScan",
        project_name="ProjectY",
        create_if_missing=True,
        params=mock_params
    )

    assert code == "NEW_SCAN_CODE"
    assert scan_id == 555
    mock_resolve_proj.assert_called_once_with(mock_workbench, "ProjectY", create_if_missing=True)
    assert mock_get_scans.call_count == 2
    mock_create_scan.assert_called_once_with("NewScan", "PROJ_Y", git_url=None, git_branch=None, git_tag=None, git_depth=None)
    assert mock_sleep.call_count >= 1 # Ensure sleep was called while waiting

@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
def test_resolve_scan_project_scope_not_found_no_create(mock_get_scans, mock_resolve_proj, mock_workbench, mock_params):
    mock_resolve_proj.return_value = "PROJ_Z"
    mock_get_scans.return_value = [] # Scan not found

    mock_params.command = 'show-results' # create_if_missing is False

    with pytest.raises(ScanNotFoundError, match="Scan 'MissingScan' not found"):
        _resolve_scan(
            mock_workbench, # Use mock_workbench fixture
            scan_name="MissingScan",
            project_name="ProjectZ",
            create_if_missing=False,
            params=mock_params
        )
    mock_resolve_proj.assert_called_once()
    mock_get_scans.assert_called_once()

def test_resolve_scan_global_scope_create_error(mock_workbench, mock_params):
    # Cannot create in global scope
    with pytest.raises(ValueError, match="Cannot create a scan.*without specifying a --project-name"):
        _resolve_scan(
            mock_workbench, # Use mock_workbench fixture
            scan_name="AnyScan",
            project_name=None, # Global scope
            create_if_missing=True, # But create requested
            params=mock_params
        )

@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
@patch('workbench_agent.utils._ensure_scan_compatibility') # Mock compatibility check
def test_resolve_scan_triggers_compatibility_check(mock_compat_check, mock_get_scans, mock_resolve_proj, mock_workbench, mock_params):
    mock_resolve_proj.return_value = "PROJ_W"
    existing_scan = {"name": "ScanCompat", "code": "SCAN_C", "id": 777}
    mock_get_scans.return_value = [existing_scan]

    mock_params.command = 'scan' # create_if_missing is True

    code, scan_id = _resolve_scan(
        mock_workbench, # Use mock_workbench fixture
        scan_name="ScanCompat",
        project_name="ProjectW",
        create_if_missing=True, # Trigger check
        params=mock_params
    )

    assert code == "SCAN_C"
    assert scan_id == 777
    mock_compat_check.assert_called_once_with(mock_params, existing_scan, "SCAN_C")


# --- MOVED TESTS for _ensure_scan_compatibility ---
def test_ensure_scan_compatibility_git_branch_mismatch(mock_params): # Use mock_params fixture
    mock_params.command = 'scan-git'
    mock_params.git_url = "http://git.com"
    mock_params.git_branch = "develop" # Requesting develop
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"} # Exists with main
    with pytest.raises(CompatibilityError, match="already exists with branch 'main'"):
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GITSCAN")

def test_ensure_scan_compatibility_git_tag_vs_branch(mock_params): # Use mock_params fixture
    mock_params.command = 'scan-git'
    mock_params.git_url = "http://git.com"
    mock_params.git_tag = "v1.0" # Requesting tag
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"} # Exists with branch
    with pytest.raises(CompatibilityError, match="exists with ref type 'branch'.*specified ref type 'tag'"):
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GITSCAN")

def test_ensure_scan_compatibility_da_vs_non_da(mock_params):
    mock_params.command = 'import-da' # Requesting DA import
    existing_scan_info = {"name": "NormalScan", "code": "NSC", "id": 2} # Exists as non-DA
    with pytest.raises(CompatibilityError, match="exists but is not a Dependency Analysis scan"):
        _ensure_scan_compatibility(mock_params, existing_scan_info, "NSC")

def test_ensure_scan_compatibility_non_da_vs_da(mock_params):
    mock_params.command = 'scan' # Requesting normal scan
    existing_scan_info = {"name": "DAScan", "code": "DSC", "id": 3, "scan_type": "dependency_analysis"} # Exists as DA
    with pytest.raises(CompatibilityError, match="exists but is a Dependency Analysis scan"):
        _ensure_scan_compatibility(mock_params, existing_scan_info, "DSC")

def test_ensure_scan_compatibility_no_conflict(mock_params):
    mock_params.command = 'scan' # Normal scan
    existing_scan_info = {"name": "NormalScan", "code": "NSC", "id": 4} # Normal scan exists
    # Should not raise any exception
    try:
        _ensure_scan_compatibility(mock_params, existing_scan_info, "NSC")
    except CompatibilityError:
        pytest.fail("CompatibilityError raised unexpectedly")

