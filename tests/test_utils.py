# /Users/tomasegonzalez/Projects/workbench-agent/tests/test_utils.py

import pytest
import argparse
import time
import json # Added for _save_results_to_file test
import os # Added for _save_results_to_file test
from unittest.mock import MagicMock, patch, mock_open # Added mock_open

# --- Updated Imports ---
from workbench_agent.utils import (
    _resolve_project,
    _resolve_scan,
    _execute_standard_scan_flow,
    # fetch_and_process_results, # Removed - function doesn't exist in provided utils.py
    _save_report_content,
    _ensure_scan_compatibility,
    format_duration,            # Added
    # _print_operation_summary, # Skipping test - primarily printing
    # _fetch_display_save_results, # Skipping test - better for integration
    _save_results_to_file       # Added
)
from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ConfigurationError,
    # AuthenticationError, # Not directly raised/tested here
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
# Import Workbench needed for type hinting/mocking
from workbench_agent.api import Workbench

# --- Fixtures (remain the same) ---
@pytest.fixture
def mock_workbench(mocker): # Use mocker fixture for MagicMock
    workbench = mocker.MagicMock(spec=Workbench) # Use spec for better mocking
    workbench.list_projects.return_value = [
        {"name": "test_project", "code": "TEST_PROJECT", "project_name": "test_project", "project_code": "TEST_PROJECT"} # Ensure both names exist if utils uses them
    ]
    # Simulate get_project_scans which is often used by _resolve_scan
    workbench.get_project_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123", "project_code": "TEST_PROJECT"} # Add project_code if needed
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
    # Add defaults needed by moved tests and others
    params.command = None
    params.project_name = None # Default to None, set in tests
    params.scan_name = None # Default to None, set in tests
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.git_depth = None
    # Add defaults for _execute_standard_scan_flow if needed
    params.limit = 10
    params.sensitivity = 5.0
    params.autoid_file_licenses = False
    params.autoid_file_copyrights = False
    params.autoid_pending_ids = False
    params.delta_scan = False
    params.id_reuse = False
    params.id_reuse_type = None
    params.id_reuse_source = None
    params.run_dependency_analysis = False
    # Add defaults for result fetching/display (though function test removed)
    params.show_licenses = False
    params.show_components = False
    params.show_dependencies = False
    params.show_scan_metrics = False
    params.show_policy_warnings = False
    params.path_result = None
    return params

# --- Tests for _resolve_project (remain the same) ---
def test_resolve_project_success(mock_workbench):
    # Ensure mock returns project_name and project_code as used in utils.py
    mock_workbench.list_projects.return_value = [{"project_name": "test_project", "project_code": "TEST_PROJECT"}]
    result = _resolve_project(mock_workbench, "test_project")
    assert result == "TEST_PROJECT"
    # list_projects in utils.py doesn't take project_name arg
    mock_workbench.list_projects.assert_called_once_with()

def test_resolve_project_not_found_no_create(mock_workbench):
    mock_workbench.list_projects.return_value = [] # Simulate not found
    with pytest.raises(ProjectNotFoundError, match="Project 'nonexistent_project' not found"):
        _resolve_project(mock_workbench, "nonexistent_project", create_if_missing=False)

# Test for create_if_missing=True finding existing project (no ProjectExistsError expected from _resolve_project)
def test_resolve_project_found_create_no_error(mock_workbench):
    mock_workbench.list_projects.return_value = [{"project_name": "test_project", "project_code": "EXISTING_CODE"}]
    result = _resolve_project(mock_workbench, "test_project", create_if_missing=True)
    assert result == "EXISTING_CODE"
    mock_workbench.create_project.assert_not_called() # Should not attempt creation

# Test for create_if_missing=True, not found initially, create succeeds
@patch('workbench_agent.utils.Workbench.create_project')
def test_resolve_project_create_success(mock_create_proj, mock_workbench):
    mock_workbench.list_projects.side_effect = [
        [], # Not found initially
        # Note: The current utils.py logic doesn't re-list after successful creation,
        # it directly uses the code returned by create_project.
    ]
    mock_create_proj.return_value = "NEW_CODE" # Simulate create returning code

    result = _resolve_project(mock_workbench, "NewProject", create_if_missing=True)

    assert result == "NEW_CODE"
    assert mock_workbench.list_projects.call_count == 1 # Only initial list call
    mock_create_proj.assert_called_once_with("NewProject")

# Test for create_if_missing=True, not found, create raises ProjectExistsError (race condition)
@patch('workbench_agent.utils.Workbench.create_project', side_effect=ProjectExistsError("Exists on create"))
def test_resolve_project_create_race_condition(mock_create_proj, mock_workbench):
    # First list finds nothing
    # Second list (after create fails) finds the existing one
    mock_workbench.list_projects.side_effect = [
        [], # Not found initially
        [{"project_name": "NewProject", "project_code": "EXISTING_CODE_RACE"}] # Found after create fails
    ]

    result = _resolve_project(mock_workbench, "NewProject", create_if_missing=True)

    # Should recover and return the existing code
    assert result == "EXISTING_CODE_RACE"
    assert mock_workbench.list_projects.call_count == 2 # Initial list + list after create fails
    mock_create_proj.assert_called_once_with("NewProject")

def test_resolve_project_api_error_list(mock_workbench):
    mock_workbench.list_projects.side_effect = ApiError("API error")
    with pytest.raises(ApiError): # utils.py doesn't wrap this specific error
        _resolve_project(mock_workbench, "test_project")

def test_resolve_project_network_error_list(mock_workbench):
    mock_workbench.list_projects.side_effect = NetworkError("Network error")
    with pytest.raises(NetworkError): # utils.py doesn't wrap this specific error
        _resolve_project(mock_workbench, "test_project")

@patch('workbench_agent.utils.Workbench.create_project', side_effect=ApiError("Create API error"))
def test_resolve_project_api_error_create(mock_create_proj, mock_workbench):
    mock_workbench.list_projects.return_value = [] # Not found initially
    with pytest.raises(ApiError, match="Failed to create project 'NewProject': API error: Create API error"):
        _resolve_project(mock_workbench, "NewProject", create_if_missing=True)
    mock_create_proj.assert_called_once()


# --- Tests for _resolve_scan (mostly remain the same, verify context) ---
def test_resolve_scan_success_project_scope(mock_workbench, mock_params):
    # Setup
    mock_params.project_name = "test_project"
    mock_params.scan_name = "test_scan"
    # Mock _resolve_project call within _resolve_scan
    with patch('workbench_agent.utils._resolve_project', return_value="TEST_PROJECT") as mock_res_proj:
        result = _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=False, params=mock_params)

    assert result == ("TEST_SCAN", 123) # ID is int
    mock_res_proj.assert_called_once_with(mock_workbench, "test_project", create_if_missing=False)
    mock_workbench.get_project_scans.assert_called_once_with("TEST_PROJECT") # No scan_name filter in API call
    mock_workbench.list_scans.assert_not_called()

def test_resolve_scan_success_global_scope(mock_workbench, mock_params):
    # Setup
    mock_params.project_name = None
    mock_params.scan_name = "global_scan"
    mock_workbench.list_scans.return_value = [{"name": "global_scan", "code": "GLOBAL_SCAN", "id": "456"}]

    result = _resolve_scan(mock_workbench, "global_scan", project_name=None, create_if_missing=False, params=mock_params)

    assert result == ("GLOBAL_SCAN", 456) # ID is int
    mock_workbench.list_scans.assert_called_once_with() # No scan_name filter in API call
    mock_workbench.get_project_scans.assert_not_called()

def test_resolve_scan_not_found_project_scope(mock_workbench, mock_params):
    mock_params.project_name = "test_project"
    mock_params.scan_name = "nonexistent_scan"
    mock_workbench.get_project_scans.return_value = [] # Simulate not found

    with patch('workbench_agent.utils._resolve_project', return_value="TEST_PROJECT"):
        with pytest.raises(ScanNotFoundError, match="Scan 'nonexistent_scan' not found in project 'test_project'"):
            _resolve_scan(mock_workbench, "nonexistent_scan", "test_project", create_if_missing=False, params=mock_params)

def test_resolve_scan_not_found_global_scope(mock_workbench, mock_params):
    mock_params.project_name = None
    mock_params.scan_name = "nonexistent_scan"
    mock_workbench.list_scans.return_value = [] # Simulate not found

    with pytest.raises(ScanNotFoundError, match="Scan 'nonexistent_scan' not found globally"): # Match updated message
        _resolve_scan(mock_workbench, "nonexistent_scan", project_name=None, create_if_missing=False, params=mock_params)

# Test create_if_missing=True finds existing scan (no ScanExistsError expected from _resolve_scan)
@patch('workbench_agent.utils._ensure_scan_compatibility')
def test_resolve_scan_found_create_no_error(mock_compat_check, mock_workbench, mock_params):
    mock_params.project_name = "test_project"
    mock_params.scan_name = "test_scan"
    mock_params.command = 'scan' # A command where create_if_missing might be True

    with patch('workbench_agent.utils._resolve_project', return_value="TEST_PROJECT"):
        code, scan_id = _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=True, params=mock_params)

    assert code == "TEST_SCAN"
    assert scan_id == 123
    mock_workbench.create_webapp_scan.assert_not_called()
    mock_compat_check.assert_called_once() # Compatibility check should still run

def test_resolve_scan_api_error_project_scope(mock_workbench, mock_params):
    mock_params.project_name = "test_project"
    mock_params.scan_name = "test_scan"
    mock_workbench.get_project_scans.side_effect = ApiError("API error")

    with patch('workbench_agent.utils._resolve_project', return_value="TEST_PROJECT"):
        with pytest.raises(ApiError, match="Failed to list scans in project 'test_project' while resolving 'test_scan': API error"):
            _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=False, params=mock_params)

def test_resolve_scan_network_error_project_scope(mock_workbench, mock_params):
    mock_params.project_name = "test_project"
    mock_params.scan_name = "test_scan"
    mock_workbench.get_project_scans.side_effect = NetworkError("Network error")

    with patch('workbench_agent.utils._resolve_project', return_value="TEST_PROJECT"):
        with pytest.raises(ApiError, match="Failed to list scans in project 'test_project' while resolving 'test_scan': Network error"): # Wrapped in ApiError
            _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=False, params=mock_params)

# --- Tests for _execute_standard_scan_flow (verify context) ---
def test_execute_standard_scan_flow_success(mock_workbench, mock_params):
    # Assume start_scan and wait_for_scan_to_finish succeed via mock_workbench
    mock_params.project_name = "TEST_PROJECT_NAME" # Need project name for reuse lookup logic

    # Function should now return scan_completed, da_completed flags, and durations
    scan_completed, da_completed, durations = _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", 123)

    # Verify the function calls
    mock_workbench.assert_process_can_start.assert_called_once_with("SCAN", "TEST_SCAN", mock_params.scan_number_of_tries, mock_params.scan_wait_time)
    mock_workbench.run_scan.assert_called_once_with(
        "TEST_SCAN",
        mock_params.limit, mock_params.sensitivity, mock_params.autoid_file_licenses,
        mock_params.autoid_file_copyrights, mock_params.autoid_pending_ids, mock_params.delta_scan,
        mock_params.id_reuse, None, None # api_reuse_type, resolved_code_for_reuse
    )
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with(
        "SCAN", "TEST_SCAN", mock_params.scan_number_of_tries, mock_params.scan_wait_time
    )
    
    # Check return values
    assert scan_completed is True
    assert da_completed is False  # DA is not requested by default in test params
    assert isinstance(durations, dict)
    assert "kb_scan" in durations
    assert "dependency_analysis" in durations

# Test ID Reuse Logic within _execute_standard_scan_flow
@patch("workbench_agent.utils._resolve_project") # Mock project lookup for reuse
def test_execute_standard_scan_flow_id_reuse_project(mock_resolve_proj_reuse, mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "project"
    mock_params.id_reuse_source = "ReuseSourceProject"
    mock_params.project_name = "CurrentProject" # Needed for context
    mock_resolve_proj_reuse.return_value = "REUSE_PROJ_CODE"

    scan_completed, da_completed, durations = _execute_standard_scan_flow(mock_workbench, mock_params, "CURRENT_PROJ_CODE", "CURRENT_SCAN_CODE", 123)

    mock_resolve_proj_reuse.assert_called_once_with(mock_workbench, "ReuseSourceProject", create_if_missing=False)
    mock_workbench.run_scan.assert_called_once_with(
        "CURRENT_SCAN_CODE",
        mock_params.limit, mock_params.sensitivity, mock_params.autoid_file_licenses,
        mock_params.autoid_file_copyrights, mock_params.autoid_pending_ids, mock_params.delta_scan,
        True, "specific_project", "REUSE_PROJ_CODE" # Check reuse args
    )
    assert scan_completed is True
    assert isinstance(durations, dict)

@patch("workbench_agent.utils._resolve_scan") # Mock scan lookup for reuse
def test_execute_standard_scan_flow_id_reuse_scan_local(mock_resolve_scan_reuse, mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "ReuseSourceScan"
    mock_params.project_name = "CurrentProject" # Needed for local lookup
    # Simulate finding the reuse scan in the *current* project
    mock_resolve_scan_reuse.return_value = ("REUSE_SCAN_CODE", 456)

    scan_completed, da_completed, durations = _execute_standard_scan_flow(mock_workbench, mock_params, "CURRENT_PROJ_CODE", "CURRENT_SCAN_CODE", 123)

    # Check that _resolve_scan was called for reuse lookup within the current project
    mock_resolve_scan_reuse.assert_called_once_with(
        mock_workbench, "ReuseSourceScan", project_name="CurrentProject", create_if_missing=False, params=mock_params
    )
    mock_workbench.run_scan.assert_called_once_with(
        "CURRENT_SCAN_CODE",
        mock_params.limit, mock_params.sensitivity, mock_params.autoid_file_licenses,
        mock_params.autoid_file_copyrights, mock_params.autoid_pending_ids, mock_params.delta_scan,
        True, "specific_scan", "REUSE_SCAN_CODE" # Check reuse args
    )
    assert scan_completed is True
    assert isinstance(durations, dict)

@patch("workbench_agent.utils._resolve_scan") # Mock scan lookup for reuse
def test_execute_standard_scan_flow_id_reuse_scan_global(mock_resolve_scan_reuse, mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "ReuseSourceScan"
    mock_params.project_name = "CurrentProject"
    # Simulate *not* finding in current project, then finding globally
    mock_resolve_scan_reuse.side_effect = [
        ScanNotFoundError("Not in current"), # First call (local) fails
        ("REUSE_SCAN_CODE_GLOBAL", 789)      # Second call (global) succeeds
    ]

    scan_completed, da_completed, durations = _execute_standard_scan_flow(mock_workbench, mock_params, "CURRENT_PROJ_CODE", "CURRENT_SCAN_CODE", 123)

    # Check that _resolve_scan was called twice (local then global)
    assert mock_resolve_scan_reuse.call_count == 2
    mock_resolve_scan_reuse.assert_any_call(
        mock_workbench, "ReuseSourceScan", project_name="CurrentProject", create_if_missing=False, params=mock_params
    )
    mock_resolve_scan_reuse.assert_any_call(
        mock_workbench, "ReuseSourceScan", project_name=None, create_if_missing=False, params=mock_params # Global call
    )
    mock_workbench.run_scan.assert_called_once_with(
        "CURRENT_SCAN_CODE",
        mock_params.limit, mock_params.sensitivity, mock_params.autoid_file_licenses,
        mock_params.autoid_file_copyrights, mock_params.autoid_pending_ids, mock_params.delta_scan,
        True, "specific_scan", "REUSE_SCAN_CODE_GLOBAL" # Check reuse args
    )
    assert scan_completed is True
    assert isinstance(durations, dict)

@patch("workbench_agent.utils._resolve_scan", side_effect=ValidationError("Global lookup failed")) # Mock scan lookup for reuse
def test_execute_standard_scan_flow_id_reuse_scan_fails(mock_resolve_scan_reuse, mock_workbench, mock_params):
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "NonExistentScan"
    mock_params.project_name = "CurrentProject"

    with pytest.raises(ValidationError, match="Error looking up scan code 'NonExistentScan' for reuse"):
        _execute_standard_scan_flow(mock_workbench, mock_params, "CURRENT_PROJ_CODE", "CURRENT_SCAN_CODE", 123)

    assert mock_resolve_scan_reuse.call_count >= 1 # At least local lookup attempted
    mock_workbench.run_scan.assert_not_called() # Should fail before run_scan

# Test with dependency analysis enabled
def test_execute_standard_scan_flow_with_da(mock_workbench, mock_params):
    mock_params.project_name = "TEST_PROJECT_NAME"
    mock_params.run_dependency_analysis = True

    scan_completed, da_completed, durations = _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", 123)

    # Verify both scan and DA were started and completed
    mock_workbench.assert_process_can_start.assert_any_call("SCAN", "TEST_SCAN", mock_params.scan_number_of_tries, mock_params.scan_wait_time)
    mock_workbench.wait_for_scan_to_finish.assert_any_call(
        "SCAN", "TEST_SCAN", mock_params.scan_number_of_tries, mock_params.scan_wait_time
    )
    mock_workbench.assert_process_can_start.assert_any_call("DEPENDENCY_ANALYSIS", "TEST_SCAN", mock_params.scan_number_of_tries, mock_params.scan_wait_time)
    mock_workbench.start_dependency_analysis.assert_called_once_with("TEST_SCAN", import_only=False)
    mock_workbench.wait_for_scan_to_finish.assert_any_call(
        "DEPENDENCY_ANALYSIS", "TEST_SCAN", mock_params.scan_number_of_tries, mock_params.scan_wait_time
    )
    
    # Check that both flags are True
    assert scan_completed is True
    assert da_completed is True
    assert isinstance(durations, dict)
    assert "kb_scan" in durations
    assert "dependency_analysis" in durations

# Other error tests for _execute_standard_scan_flow remain largely the same, just ensure mock_params has project_name if needed
def test_execute_standard_scan_flow_start_api_error(mock_workbench, mock_params):
    mock_params.project_name = "TEST_PROJECT_NAME"
    mock_workbench.run_scan.side_effect = ApiError("API error on start") # run_scan is called now
    with pytest.raises(WorkbenchAgentError, match="Unexpected error starting KB Scan: API error on start"): # Wrapped now
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", 123)
    mock_workbench.wait_for_scan_to_finish.assert_not_called()

def test_execute_standard_scan_flow_wait_network_error(mock_workbench, mock_params):
    mock_params.project_name = "TEST_PROJECT_NAME"
    mock_workbench.wait_for_scan_to_finish.side_effect = NetworkError("Network error on wait")
    with pytest.raises(NetworkError): # Not wrapped
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", 123)
    mock_workbench.run_scan.assert_called_once()

def test_execute_standard_scan_flow_wait_process_error(mock_workbench, mock_params):
    mock_params.project_name = "TEST_PROJECT_NAME"
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessError("Process error on wait")
    with pytest.raises(ProcessError): # Not wrapped
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", 123)

def test_execute_standard_scan_flow_wait_process_timeout(mock_workbench, mock_params):
    mock_params.project_name = "TEST_PROJECT_NAME"
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Process timeout on wait")
    with pytest.raises(ProcessTimeoutError): # Not wrapped
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", 123)


# --- REMOVED Tests for fetch_and_process_results ---
# Reason: The function fetch_and_process_results does not exist in the provided utils.py.
# The replacement _fetch_display_save_results is complex and better suited for integration tests.


# --- Tests for _save_report_content (remain the same) ---
def test_save_report_content_success(mock_workbench):
    response = MagicMock()
    response.content = b"test content"
    response.headers = {'content-type': 'text/plain'}
    response.encoding = 'utf-8' # Simulate encoding being set

    # Use mock_open from unittest.mock
    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(response, "/save/path", "scan", "MyScan", "txt")
        expected_path = os.path.join("/save", "path", "scan_MyScan_txt.txt") # Check generated filename
        mock_file.assert_called_once_with(expected_path, "w", encoding='utf-8') # Check mode and encoding
        mock_file().write.assert_called_once_with("test content") # Check content decoded

def test_save_report_content_binary(mock_workbench):
    response = MagicMock()
    response.content = b"\x80binary data" # Non-utf8 data
    response.headers = {'content-type': 'application/octet-stream'}
    response.encoding = None # Simulate no encoding

    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(response, "/save/path", "project", "MyProj", "bin_report")
        # Generate expected filename (extension might be 'bin' or 'txt' depending on map)
        # Assuming 'bin_report' is not in map, defaults to .txt
        expected_path = os.path.join("/save", "path", "project_MyProj_bin_report.txt")
        mock_file.assert_called_once_with(expected_path, "wb") # Check binary mode
        mock_file().write.assert_called_once_with(b"\x80binary data") # Check binary content

def test_save_report_content_dict(mock_workbench):
    content = {"key": "value", "list": [1, 2]}
    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(content, "/save/path", "scan", "MyScan", "results")
        expected_path = os.path.join("/save", "path", "scan_MyScan_results.json") # Should be .json
        mock_file.assert_called_once_with(expected_path, "w", encoding='utf-8')
        # Check that json.dumps was effectively called (content written should be JSON string)
        written_content = mock_file().write.call_args[0][0]
        assert written_content == json.dumps(content, indent=2)

def test_save_report_content_file_system_error(mock_workbench):
    response = MagicMock()
    response.content = b"test content"
    response.headers = {'content-type': 'application/pdf'}
    response.encoding = None

    with patch("builtins.open", mock_open()) as mock_file:
        mock_file.side_effect = IOError("Permission denied") # Simulate write error
        with pytest.raises(FileSystemError, match="Failed to write report to '.*/project_MyProj_pdf.pdf': Permission denied"):
            _save_report_content(response, "/locked/dir", "project", "MyProj", "pdf")

# --- ADDED Tests for format_duration ---
@pytest.mark.parametrize("seconds, expected", [
    (0, "0 seconds"),
    (1, "1 second"),
    (59, "59 seconds"),
    (60, "1 minutes"),
    (61, "1 minutes, 1 seconds"),
    (119, "1 minutes, 59 seconds"),
    (120, "2 minutes"),
    (121, "2 minutes, 1 seconds"),
    (3600, "60 minutes"),
    (3661, "61 minutes, 1 seconds"),
    (7322.5, "122 minutes, 3 seconds"), # Test rounding
    (None, "N/A"),
    ("abc", "Invalid Duration"),
])
def test_format_duration(seconds, expected):
    assert format_duration(seconds) == expected

# --- ADDED Tests for _save_results_to_file ---
@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_save_results_to_file_success(mock_makedirs, mock_open_file):
    results_data = {"scan_metrics": {"total": 100}, "kb_licenses": [{"id": "MIT"}]}
    filepath = "/output/dir/results.json"
    scan_code = "SCAN123"

    _save_results_to_file(filepath, results_data, scan_code)

    mock_makedirs.assert_called_once_with("/output/dir", exist_ok=True)
    mock_open_file.assert_called_once_with(filepath, 'w', encoding='utf-8')
    handle = mock_open_file()
    # Check that json.dump was called with the correct data and indent
    written_content = handle.write.call_args[0][0]
    assert written_content == json.dumps(results_data, indent=2, ensure_ascii=False)

@patch("os.makedirs", side_effect=OSError("Cannot create dir"))
def test_save_results_to_file_makedirs_error(mock_makedirs):
    results_data = {"key": "value"}
    filepath = "/unwritable/results.json"
    scan_code = "SCAN123"

    # Should log error and print warning, but not raise exception
    _save_results_to_file(filepath, results_data, scan_code)
    # Add assertion for log capture if logging is tested

@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_save_results_to_file_write_error(mock_makedirs, mock_open_file):
    results_data = {"key": "value"}
    filepath = "/output/results.json"
    scan_code = "SCAN123"
    mock_open_file.side_effect = IOError("Disk full")

    # Should log error and print warning, but not raise exception
    _save_results_to_file(filepath, results_data, scan_code)
    mock_makedirs.assert_called_once()
    mock_open_file.assert_called_once()
    # Add assertion for log capture if logging is tested


# --- MOVED TESTS for _resolve_scan (More Cases - remain the same) ---
@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
@patch('workbench_agent.utils.Workbench.create_webapp_scan')
@patch('time.sleep', return_value=None) # Mock time.sleep
def test_resolve_scan_project_scope_create_success(mock_sleep, mock_create_scan, mock_get_scans, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.project_name = "ProjectY" # Set project name on params
    mock_params.scan_name = "NewScan"
    mock_params.command = 'scan' # A command where create_if_missing is True
    mock_resolve_proj.return_value = "PROJ_Y"
    # First call to get_project_scans finds nothing
    # Second call after creation finds the new scan
    mock_get_scans.side_effect = [
        [], # Scan not found initially
        [{"name": "NewScan", "code": "NEW_SCAN_CODE", "id": "555"}] # Found after creation (ID as string)
    ]
    mock_create_scan.return_value = True # Simulate successful trigger

    code, scan_id = _resolve_scan(
        mock_workbench,
        scan_name="NewScan",
        project_name="ProjectY",
        create_if_missing=True,
        params=mock_params
    )

    assert code == "NEW_SCAN_CODE"
    assert scan_id == 555 # Check conversion to int
    mock_resolve_proj.assert_called_once_with(mock_workbench, "ProjectY", create_if_missing=True)
    assert mock_get_scans.call_count == 2
    mock_create_scan.assert_called_once_with(project_code="PROJ_Y", scan_name="NewScan", git_url=None, git_branch=None, git_tag=None, git_depth=None)
    mock_sleep.assert_called_once_with(2) # Ensure sleep was called while waiting

@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
def test_resolve_scan_project_scope_not_found_no_create(mock_get_scans, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.project_name = "ProjectZ"
    mock_params.scan_name = "MissingScan"
    mock_params.command = 'show-results' # create_if_missing is False
    mock_resolve_proj.return_value = "PROJ_Z"
    mock_get_scans.return_value = [] # Scan not found

    with pytest.raises(ScanNotFoundError, match="Scan 'MissingScan' not found in project 'ProjectZ'"):
        _resolve_scan(
            mock_workbench,
            scan_name="MissingScan",
            project_name="ProjectZ",
            create_if_missing=False,
            params=mock_params
        )
    mock_resolve_proj.assert_called_once()
    mock_get_scans.assert_called_once()

def test_resolve_scan_global_scope_create_error(mock_workbench, mock_params):
    mock_params.project_name = None # Global scope
    mock_params.scan_name = "AnyScan"
    # Cannot create in global scope
    with pytest.raises(ConfigurationError, match="Cannot create a scan.*without specifying a --project-name"): # Check specific exception
        _resolve_scan(
            mock_workbench,
            scan_name="AnyScan",
            project_name=None, # Global scope
            create_if_missing=True, # But create requested
            params=mock_params
        )

@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
@patch('workbench_agent.utils._ensure_scan_compatibility') # Mock compatibility check
def test_resolve_scan_triggers_compatibility_check(mock_compat_check, mock_get_scans, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.project_name = "ProjectW"
    mock_params.scan_name = "ScanCompat"
    mock_params.command = 'scan' # create_if_missing is True
    mock_resolve_proj.return_value = "PROJ_W"
    existing_scan = {"name": "ScanCompat", "code": "SCAN_C", "id": "777"} # ID as string
    mock_get_scans.return_value = [existing_scan]

    code, scan_id = _resolve_scan(
        mock_workbench,
        scan_name="ScanCompat",
        project_name="ProjectW",
        create_if_missing=True, # Trigger check
        params=mock_params
    )

    assert code == "SCAN_C"
    assert scan_id == 777 # Check conversion
    mock_compat_check.assert_called_once_with(mock_params, existing_scan, "SCAN_C")


# --- MOVED TESTS for _ensure_scan_compatibility (verify context/corrections) ---
def test_ensure_scan_compatibility_git_branch_mismatch(mock_params):
    mock_params.command = 'scan-git'
    mock_params.git_url = "http://git.com"
    mock_params.git_branch = "develop" # Requesting develop
    # Simulate API response with git_ref_type
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"}
    with pytest.raises(CompatibilityError, match="already exists for branch 'main'"): # Match updated message
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GITSCAN")

def test_ensure_scan_compatibility_git_tag_vs_branch(mock_params):
    mock_params.command = 'scan-git'
    mock_params.git_url = "http://git.com"
    mock_params.git_tag = "v1.0" # Requesting tag
    # Simulate API response with git_ref_type
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"}
    with pytest.raises(CompatibilityError, match="exists with ref type 'branch'.*specified ref type 'tag'"): # Match updated message
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GITSCAN")

# Test case: Requesting branch, existing is tag
def test_ensure_scan_compatibility_git_branch_vs_tag(mock_params):
    mock_params.command = 'scan-git'
    mock_params.git_url = "http://git.com"
    mock_params.git_branch = "main" # Requesting branch
    # Simulate API response with git_ref_type as tag
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "v1.0", "git_ref_type": "tag"}
    with pytest.raises(CompatibilityError, match="exists with ref type 'tag'.*specified ref type 'branch'"):
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GITSCAN")

# Test case: Requesting different tag
def test_ensure_scan_compatibility_git_tag_mismatch(mock_params):
    mock_params.command = 'scan-git'
    mock_params.git_url = "http://git.com"
    mock_params.git_tag = "v2.0" # Requesting v2.0
    # Simulate API response with git_ref_type as tag v1.0
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "v1.0", "git_ref_type": "tag"}
    with pytest.raises(CompatibilityError, match="already exists for tag 'v1.0'"): # Match updated message
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GITSCAN")

# Test case: Requesting different URL
def test_ensure_scan_compatibility_git_url_mismatch(mock_params):
    mock_params.command = 'scan-git'
    mock_params.git_url = "http://another-git.com" # Requesting different URL
    mock_params.git_branch = "main"
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"}
    with pytest.raises(CompatibilityError, match="different Git repository"):
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GITSCAN")

# Test case: Requesting 'scan' (path upload) when existing is Git
def test_ensure_scan_compatibility_scan_vs_git(mock_params):
    mock_params.command = 'scan' # Requesting path upload
    mock_params.path = "/some/path"
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"}
    with pytest.raises(CompatibilityError, match="created for Git scanning.*cannot be reused for code upload"):
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GITSCAN")

# Test case: Requesting 'scan-git' when existing is path upload
def test_ensure_scan_compatibility_git_vs_scan(mock_params):
    mock_params.command = 'scan-git' # Requesting git
    mock_params.git_url = "http://git.com"
    mock_params.git_branch = "main"
    existing_scan_info = {"name": "PathScan", "code": "PATHSCAN", "id": 2} # No git info
    with pytest.raises(CompatibilityError, match="created for code upload.*cannot be reused for Git scanning"):
        _ensure_scan_compatibility(mock_params, existing_scan_info, "PATHSCAN")

# DA vs non-DA tests seem okay based on utils.py logic (which doesn't check scan_type)
# The utils.py _ensure_scan_compatibility doesn't actually check DA vs non-DA.
# Let's remove those specific tests as they don't reflect the current implementation.
# def test_ensure_scan_compatibility_da_vs_non_da(mock_params): ...
# def test_ensure_scan_compatibility_non_da_vs_da(mock_params): ...

def test_ensure_scan_compatibility_no_conflict_scan(mock_params):
    mock_params.command = 'scan' # Normal scan
    existing_scan_info = {"name": "NormalScan", "code": "NSC", "id": 4} # Normal scan exists
    try:
        _ensure_scan_compatibility(mock_params, existing_scan_info, "NSC")
    except CompatibilityError:
        pytest.fail("CompatibilityError raised unexpectedly for scan vs scan")

def test_ensure_scan_compatibility_no_conflict_git(mock_params):
    mock_params.command = 'scan-git' # Git scan
    mock_params.git_url = "http://git.com"
    mock_params.git_branch = "main"
    existing_scan_info = {"name": "GitScan", "code": "GSC", "id": 5, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"} # Matching Git scan
    try:
        _ensure_scan_compatibility(mock_params, existing_scan_info, "GSC")
    except CompatibilityError:
        pytest.fail("CompatibilityError raised unexpectedly for git vs git (match)")

def test_ensure_scan_compatibility_no_conflict_import_da(mock_params):
    mock_params.command = 'import-da' # DA import
    existing_scan_info = {"name": "AnyScan", "code": "ASC", "id": 6} # Can reuse any scan type
    try:
        _ensure_scan_compatibility(mock_params, existing_scan_info, "ASC")
    except CompatibilityError:
        pytest.fail("CompatibilityError raised unexpectedly for import-da")

