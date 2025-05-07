# /Users/tomasegonzalez/Projects/workbench-agent/tests/test_utils.py

import pytest
import argparse
import time
import json # Added for _save_results_to_file test
import os # Added for _save_results_to_file test
import requests # Added for Response objects in tests
from unittest.mock import MagicMock, patch, mock_open # Added mock_open
from unittest.mock import call

# --- Updated Imports ---
from workbench_cli.utils import (
    _resolve_project,
    _resolve_scan,
    # _execute_standard_scan_flow, # Removed - function has been refactored out
    # fetch_and_process_results, # Removed - function doesn't exist in provided utils.py
    _save_report_content,
    _ensure_scan_compatibility,
    format_duration,            # Added
    # _print_operation_summary, # Skipping test - primarily printing
    # _fetch_display_save_results, # Skipping test - better for integration
    _save_results_to_file,       # Added
    _validate_reuse_source
)
from workbench_cli.exceptions import (
    WorkbenchCLIError,
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
# Import WorkbenchAPI needed for type hinting/mocking
from workbench_cli.api import WorkbenchAPI

# --- Fixtures (remain the same) ---
@pytest.fixture
def mock_workbench(mocker): # Use mocker fixture for MagicMock
    workbench = mocker.MagicMock() # Don't use spec to allow setting any attribute
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
    # Add mock for assert_process_can_start to avoid AttributeError
    workbench.assert_process_can_start = mocker.MagicMock(return_value=None)
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
    # Add defaults for id-reuse validation tests
    params.id_reuse = False
    params.id_reuse_type = None
    params.id_reuse_source = None
    # Add defaults for result fetching/display (though function test removed)
    params.show_licenses = False
    params.show_components = False
    params.show_dependencies = False
    params.show_scan_metrics = False
    params.show_policy_warnings = False
    params.path_result = None
    return params

# --- Tests for _resolve_project ---
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
def test_resolve_project_create_success(mock_workbench):
    # Configure mock_workbench.list_projects to return empty list first, simulating project not found
    mock_workbench.list_projects.return_value = [] # Not found initially
    
    # Set the return value of create_project
    mock_workbench.create_project.return_value = "NEW_CODE" # Simulate create returning code

    result = _resolve_project(mock_workbench, "NewProject", create_if_missing=True)

    assert result == "NEW_CODE"
    assert mock_workbench.list_projects.call_count == 1 # Only initial list call
    mock_workbench.create_project.assert_called_once_with("NewProject")

# Test for create_if_missing=True, not found, create raises ProjectExistsError (race condition)
def test_resolve_project_create_race_condition(mock_workbench):
    # First list finds nothing
    # Second list (after create fails) finds the existing one
    mock_workbench.list_projects.side_effect = [
        [], # Not found initially
        [{"project_name": "NewProject", "project_code": "EXISTING_CODE_RACE"}] # Found after create fails
    ]
    
    # Make create_project raise ProjectExistsError
    mock_workbench.create_project.side_effect = ProjectExistsError("Exists on create")

    result = _resolve_project(mock_workbench, "NewProject", create_if_missing=True)

    # Should recover and return the existing code
    assert result == "EXISTING_CODE_RACE"
    assert mock_workbench.list_projects.call_count == 2 # Initial list + list after create fails
    mock_workbench.create_project.assert_called_once_with("NewProject")

def test_resolve_project_api_error_create(mock_workbench):
    # Set up mock to return an empty list to trigger create path
    mock_workbench.list_projects.return_value = [] # Not found initially
    
    # Make create_project raise ApiError
    mock_workbench.create_project.side_effect = ApiError("Create API error")
    
    # Should raise ApiError - fix the expected message pattern to match actual implementation
    with pytest.raises(ApiError, match="Failed to create project 'NewProject': Create API error"):
        _resolve_project(mock_workbench, "NewProject", create_if_missing=True)
    
    # Assert that create_project was called
    mock_workbench.create_project.assert_called_once_with("NewProject")


# --- Tests for _resolve_scan ---
def test_resolve_scan_success_project_scope(mock_workbench, mock_params):
    # Setup
    mock_params.project_name = "test_project"
    mock_params.scan_name = "test_scan"
    # Mock _resolve_project call within _resolve_scan
    with patch('workbench_cli.utils._resolve_project', return_value="TEST_PROJECT") as mock_res_proj:
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

    with patch('workbench_cli.utils._resolve_project', return_value="TEST_PROJECT"):
        with pytest.raises(ScanNotFoundError, match="Scan 'nonexistent_scan' not found in the 'test_project' project"):
            _resolve_scan(mock_workbench, "nonexistent_scan", "test_project", create_if_missing=False, params=mock_params)

def test_resolve_scan_not_found_global_scope(mock_workbench, mock_params):
    mock_params.project_name = None
    mock_params.scan_name = "nonexistent_scan"
    mock_workbench.list_scans.return_value = [] # Simulate not found
    
    with pytest.raises(ScanNotFoundError, match="Scan 'nonexistent_scan' not found globally"):
        _resolve_scan(mock_workbench, "nonexistent_scan", project_name=None, create_if_missing=False, params=mock_params)

def test_resolve_scan_found_create_no_error(mock_workbench, mock_params):
    mock_params.project_name = "test_project"
    mock_params.scan_name = "test_scan"

    with patch('workbench_cli.utils._resolve_project', return_value="TEST_PROJECT"):
        result = _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=True, params=mock_params)

    assert result == ("TEST_SCAN", 123) # ID is int
    # These are the assertions that matter
    mock_workbench.create_webapp_scan.assert_not_called() # Should not attempt creation
    # No longer check compatibility here as it's now done separately

# Tests for the new _ensure_scan_compatibility function
def test_ensure_scan_compatibility_scan_command_success(mock_workbench, mock_params):
    # Setup mock scan_info response with no git info for scan command
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": None,
        "git_branch": None,
        "git_ref_type": None
    }
    
    # Setup for scan command
    mock_params.command = "scan"
    
    # Should not raise any exceptions
    _ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")
    
    # Verify scan info was requested
    mock_workbench.get_scan_information.assert_called_once_with("TEST_SCAN")

def test_ensure_scan_compatibility_scan_git_command_success(mock_workbench, mock_params):
    # Setup mock scan_info response with git info matching params
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch"
    }
    
    # Setup for scan-git command with matching git info
    mock_params.command = "scan-git"
    mock_params.git_url = "https://github.com/example/repo.git"
    mock_params.git_branch = "main"
    mock_params.git_tag = None
    mock_params.git_commit = None
    
    # Should not raise any exceptions
    _ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")
    
    # Verify scan info was requested
    mock_workbench.get_scan_information.assert_called_once_with("TEST_SCAN")

def test_ensure_scan_compatibility_scan_command_incompatible(mock_workbench, mock_params):
    # Setup mock scan_info response with git info for scan command (incompatible)
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch"
    }
    
    # Setup for scan command which is incompatible with git scans
    mock_params.command = "scan"
    
    # Should raise CompatibilityError
    with pytest.raises(CompatibilityError, match="Scan 'TEST_SCAN' was created for Git scanning .* and cannot be reused for code upload"):
        _ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")
    
    # Verify scan info was requested
    mock_workbench.get_scan_information.assert_called_once_with("TEST_SCAN")

def test_ensure_scan_compatibility_scan_git_command_incompatible_url(mock_workbench, mock_params):
    # Setup mock scan_info response with git info not matching params
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch"
    }
    
    # Setup for scan-git command with non-matching git URL
    mock_params.command = "scan-git"
    mock_params.git_url = "https://github.com/different/repo.git"
    mock_params.git_branch = "main"
    mock_params.git_tag = None
    mock_params.git_commit = None
    
    # Should raise CompatibilityError
    with pytest.raises(CompatibilityError, match="Scan 'TEST_SCAN' already exists but is configured for a different Git repository"):
        _ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")
    
    # Verify scan info was requested
    mock_workbench.get_scan_information.assert_called_once_with("TEST_SCAN")

def test_ensure_scan_compatibility_scan_git_command_incompatible_ref_type(mock_workbench, mock_params):
    # Setup mock scan_info response with git info not matching params
    mock_workbench.get_scan_information.return_value = {
        "code": "TEST_SCAN",
        "name": "Test Scan",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "v1.0.0",
        "git_ref_type": "tag"
    }
    
    # Setup for scan-git command with non-matching ref type (branch vs tag)
    mock_params.command = "scan-git"
    mock_params.git_url = "https://github.com/example/repo.git"
    mock_params.git_branch = "main"
    mock_params.git_tag = None
    mock_params.git_commit = None
    
    # Should raise CompatibilityError
    with pytest.raises(CompatibilityError, match="Scan 'TEST_SCAN' exists with ref type 'tag', but current command specified ref type 'branch'"):
        _ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")
    
    # Verify scan info was requested
    mock_workbench.get_scan_information.assert_called_once_with("TEST_SCAN")

def test_ensure_scan_compatibility_scan_not_found(mock_workbench, mock_params):
    # Setup mock scan_info to raise ScanNotFoundError
    mock_workbench.get_scan_information.side_effect = ScanNotFoundError("Scan not found")
    
    # Should not raise any exceptions, just return
    _ensure_scan_compatibility(mock_workbench, mock_params, "NONEXISTENT_SCAN")
    
    # Verify scan info was requested
    mock_workbench.get_scan_information.assert_called_once_with("NONEXISTENT_SCAN")

def test_ensure_scan_compatibility_api_error(mock_workbench, mock_params):
    # Setup mock scan_info to raise ApiError
    mock_workbench.get_scan_information.side_effect = ApiError("API Error")
    
    # Should not raise any exceptions, just return
    _ensure_scan_compatibility(mock_workbench, mock_params, "TEST_SCAN")
    
    # Verify scan info was requested
    mock_workbench.get_scan_information.assert_called_once_with("TEST_SCAN")

# Re-adding the deleted tests for _resolve_scan error handling
def test_resolve_scan_api_error_project_scope(mock_workbench, mock_params):
    mock_params.project_name = "test_project"
    mock_params.scan_name = "test_scan"
    # Mock resolves project, but get_project_scans fails
    with patch('workbench_cli.utils._resolve_project', return_value="TEST_PROJECT"):
        mock_workbench.get_project_scans.side_effect = ApiError("API Error")
        with pytest.raises(ApiError, match="Failed to list scans .* while resolving 'test_scan'"):
            _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=False, params=mock_params)

def test_resolve_scan_network_error_project_scope(mock_workbench, mock_params):
    mock_params.project_name = "test_project"
    mock_params.scan_name = "test_scan"
    # Mock resolves project, but get_project_scans fails with network error
    with patch('workbench_cli.utils._resolve_project', return_value="TEST_PROJECT"):
        mock_workbench.get_project_scans.side_effect = NetworkError("Network Failure")
        with pytest.raises(ApiError, match="Failed to list scans in the 'test_project' project while resolving 'test_scan'"):
            _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=False, params=mock_params)

# --- Tests for _save_report_content ---
def test_save_report_content_success(mock_workbench):
    content = "Sample report content in text format."
    output_dir = "/tmp"  # Use a valid directory path
    
    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(content, output_dir, "scan", "test_scan", "text")
        
    mock_file.assert_called_once_with(os.path.join(output_dir, "scan-test_scan-text.txt"), 'w', encoding='utf-8')  # File opened in text mode with encoding
    mock_file().write.assert_called_once_with(content)  # Content written directly

def test_save_report_content_binary(mock_workbench):
    binary_content = b'Some binary content'
    output_dir = "/tmp"  # Use a valid directory path
    
    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(binary_content, output_dir, "scan", "test_scan", "binary")
        
    mock_file.assert_called_once_with(os.path.join(output_dir, "scan-test_scan-binary.bin"), 'wb')  # File opened in binary mode
    mock_file().write.assert_called_once_with(binary_content)  # Binary content not encoded again

def test_save_report_content_dict(mock_workbench):
    # Dict content should be converted to JSON
    dict_content = {"key": "value", "nested": {"foo": "bar"}}
    output_dir = "/tmp"  # Use a valid directory path
    
    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(dict_content, output_dir, "scan", "test_scan", "json")
        
    mock_file.assert_called_once_with(os.path.join(output_dir, "scan-test_scan-json.json"), 'w', encoding='utf-8')  # File opened in text mode with encoding
    # Check that the dict is serialized to JSON
    mock_file().write.assert_called_once()
    written_data = mock_file().write.call_args[0][0]
    # Parse as JSON to verify it's valid
    assert json.loads(written_data) == dict_content

def test_save_report_content_file_system_error(mock_workbench):
    content = "Sample report content in text format."
    output_dir = "/tmp"  # Use a valid directory path
    
    # Path to patched file
    filepath = os.path.join(output_dir, "scan-test_scan-text.txt")
    
    # First patch os.makedirs to succeed
    with patch("os.makedirs", return_value=None):
        # Then make open raise an IOError to simulate filesystem issues
        with patch("builtins.open", side_effect=IOError("Cannot write to file")):
            with pytest.raises(FileSystemError, match=f"Failed to write report to '{filepath}'"):
                _save_report_content(content, output_dir, "scan", "test_scan", "text")

# --- Tests for format_duration ---
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
    (7322.5, "122 minutes, 2 seconds"), # Test rounding
    (None, "N/A"),
    ("abc", "Invalid Duration"),
])
def test_format_duration(seconds, expected):
    assert format_duration(seconds) == expected

# --- Tests for _save_results_to_file ---
@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_save_results_to_file_success(mock_makedirs, mock_open_file):
    # Test parameters
    data = {
        "licenses": ["MIT", "Apache-2.0"],
        "components": [
            {"name": "component1", "license": "MIT"},
            {"name": "component2", "license": "Apache-2.0"},
        ],
        "vulnerabilities": [
            {"id": "CVE-2022-1234", "component": "component1", "severity": "high"},
        ],
    }
    output_path = "/path/to/results.json"
    scan_code = "TEST_SCAN"
    
    # Run function
    _save_results_to_file(output_path, data, scan_code)
    
    # Check directory creation
    mock_makedirs.assert_called_once_with(os.path.dirname(output_path), exist_ok=True)
    
    # Check file open
    mock_open_file.assert_called_once_with(output_path, "w", encoding="utf-8")
    
    # Need to check that json.dump was called - can't check exact content because json.dump writes in chunks
    # But we can check the parsed result from what was written
    handle = mock_open_file()
    assert handle.write.called
    
    # Mock how json.dump would serialize if we need to check the content later
    with patch('json.dump') as mock_json_dump:
        _save_results_to_file(output_path, data, scan_code)
        mock_json_dump.assert_called_once()
        json_args = mock_json_dump.call_args[0]
        assert json_args[0] == data  # First arg should be the data dict

@patch("os.makedirs", side_effect=OSError("Cannot create dir"))
def test_save_results_to_file_makedirs_error(mock_makedirs):
    # Test parameters
    data = {"data": "important"}
    output_path = "/path/to/results.json"
    scan_code = "TEST_SCAN"
    
    # Run function and check if it properly handles the exception
    # The function itself doesn't raise exceptions but logs warnings
    _save_results_to_file(output_path, data, scan_code)
    
    # Verify makedirs was called
    mock_makedirs.assert_called_once_with(os.path.dirname(output_path), exist_ok=True)

@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_save_results_to_file_write_error(mock_makedirs, mock_open_file):
    # Test parameters
    data = {"data": "important"}
    output_path = "/path/to/results.json"
    scan_code = "TEST_SCAN"
    
    # Configure mock file to raise error when json.dump would call write
    mock_open_file.return_value.write.side_effect = OSError("Cannot write to file")
    
    # Run function and check if it properly handles the exception
    # The function itself doesn't raise exceptions but logs warnings
    _save_results_to_file(output_path, data, scan_code)
    
    # Verify makedirs was called
    mock_makedirs.assert_called_once_with(os.path.dirname(output_path), exist_ok=True)
    
    # Check that open was called, even though the write will fail
    mock_open_file.assert_called_once_with(output_path, "w", encoding="utf-8")

# --- Tests for _validate_reuse_source ---
def test_validate_reuse_source_none_when_disabled(mock_workbench, mock_params):
    # No id_reuse enabled
    mock_params.id_reuse = False
    mock_params.id_reuse_type = "project"
    mock_params.id_reuse_source = "some_project"
    
    # Should return (None, None) when ID reuse is disabled
    assert _validate_reuse_source(mock_workbench, mock_params) == (None, None)

@patch('workbench_cli.utils._resolve_project')
def test_validate_reuse_source_project_success(mock_resolve_project, mock_workbench, mock_params):
    # Set up params for project reuse
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "project"
    mock_params.id_reuse_source = "source_project"
    
    # Mock resolution successful
    mock_resolve_project.return_value = "SOURCE_PROJECT"
    
    # Call the function
    result = _validate_reuse_source(mock_workbench, mock_params)
    
    # Check results
    assert result == ("specific_project", "SOURCE_PROJECT")
    mock_resolve_project.assert_called_once_with(mock_workbench, "source_project", create_if_missing=False)

@patch('workbench_cli.utils._resolve_project')
def test_validate_reuse_source_project_not_found(mock_resolve_project, mock_workbench, mock_params):
    # Set up params for project reuse
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "project"
    mock_params.id_reuse_source = "nonexistent_project"
    
    # Mock resolution failing
    mock_resolve_project.side_effect = ProjectNotFoundError("Project 'nonexistent_project' not found")
    
    # Call should raise ValidationError - updated to match actual error message
    with pytest.raises(ValidationError, match="The project specified as an identification reuse source .* does not exist in Workbench"):
        _validate_reuse_source(mock_workbench, mock_params)

@patch('workbench_cli.utils._resolve_scan')
def test_validate_reuse_source_scan_local_success(mock_resolve_scan, mock_workbench, mock_params):
    # Set up params for scan reuse in the same project
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "source_scan"
    mock_params.project_name = "same_project"  # Current project (common scenario)
    
    # Mock scan resolution successful
    mock_resolve_scan.return_value = ("SOURCE_SCAN", 123)
    
    # Call the function
    result = _validate_reuse_source(mock_workbench, mock_params)
    
    # Check results
    assert result == ("specific_scan", "SOURCE_SCAN")
    # Should look up in the same project context - using project_name parameter
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, 
        "source_scan", 
        project_name="same_project", 
        create_if_missing=False, 
        params=mock_params
    )

@patch('workbench_cli.utils._resolve_scan')
def test_validate_reuse_source_scan_global_success(mock_resolve_scan, mock_workbench, mock_params):
    # Set up params for scan reuse with project:scan format
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "other_project:source_scan"
    mock_params.project_name = "current_project"  # Different from reuse source
    
    # Set up side effect for both the first (failure) and second (success) calls
    mock_resolve_scan.side_effect = [
        ScanNotFoundError("Not found in current project"),  # First call fails
        ("SOURCE_SCAN", 456)                               # Second call succeeds
    ]
    
    # Call the function
    result = _validate_reuse_source(mock_workbench, mock_params)
    
    # Check results
    assert result == ("specific_scan", "SOURCE_SCAN")
    
    # Verify that both the local lookup and global lookup were attempted
    assert mock_resolve_scan.call_count == 2
    
    # First call should be to look up in current project
    assert mock_resolve_scan.call_args_list[0] == call(
        mock_workbench,
        "other_project:source_scan",
        project_name="current_project",
        create_if_missing=False,
        params=mock_params
    )
    
    # Second call should be global lookup
    assert mock_resolve_scan.call_args_list[1] == call(
        mock_workbench,
        "other_project:source_scan",
        project_name=None,
        create_if_missing=False,
        params=mock_params
    )

@patch('workbench_cli.utils._resolve_scan')
def test_validate_reuse_source_scan_not_found(mock_resolve_scan, mock_workbench, mock_params):
    # Set up params for scan reuse
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = "nonexistent_scan"
    mock_params.project_name = "current_project"
    
    # Mock resolution failing
    mock_resolve_scan.side_effect = ScanNotFoundError("Scan 'nonexistent_scan' not found")
    
    # Call should raise ValidationError - match pattern changed to match actual error message
    with pytest.raises(ValidationError, match="The scan specified as an identification reuse source .* does not exist in Workbench"):
        _validate_reuse_source(mock_workbench, mock_params)

def test_validate_reuse_source_missing_source_project(mock_workbench, mock_params):
    # Set up params for project reuse but missing source
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "project"
    mock_params.id_reuse_source = None  # Missing source
    
    # Call should raise ConfigurationError with the correct message
    with pytest.raises(ConfigurationError, match="Missing project name in --id-reuse-source for ID reuse type 'project'"):
        _validate_reuse_source(mock_workbench, mock_params)

def test_validate_reuse_source_missing_source_scan(mock_workbench, mock_params):
    # Set up params for scan reuse but missing source
    mock_params.id_reuse = True
    mock_params.id_reuse_type = "scan"
    mock_params.id_reuse_source = None  # Missing source
    
    # Call should raise ConfigurationError with the correct message
    with pytest.raises(ConfigurationError, match="Missing scan name in --id-reuse-source for ID reuse type 'scan'"):
        _validate_reuse_source(mock_workbench, mock_params)

