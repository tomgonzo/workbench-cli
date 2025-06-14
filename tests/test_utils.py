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
    _save_report_content,
    format_duration,
    _save_results_to_file
)
from workbench_cli.exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ConfigurationError,
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

# --- Tests for _save_report_content ---
def test_save_report_content_success(mock_workbench):
    # Test saving a text response
    response = MagicMock(spec=requests.Response)
    response.content = b"Test content"
    response.headers = {"content-type": "text/plain"}
    response.encoding = "utf-8"
    
    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(response, "output_dir", "scan", "test_scan", "basic")
        mock_file.assert_called_once()
        mock_file().write.assert_called_once_with("Test content")

def test_save_report_content_binary(mock_workbench):
    # Test saving a binary response
    response = MagicMock(spec=requests.Response)
    response.content = b"\x00\x01\x02\x03"
    response.headers = {"content-type": "application/octet-stream"}
    
    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(response, "output_dir", "scan", "test_scan", "xlsx")
        mock_file.assert_called_once()
        mock_file().write.assert_called_once_with(b"\x00\x01\x02\x03")

def test_save_report_content_dict(mock_workbench):
    # Test saving a dictionary as JSON
    content = {"key": "value"}
    
    with patch("builtins.open", mock_open()) as mock_file:
        _save_report_content(content, "output_dir", "scan", "test_scan", "json")
        mock_file.assert_called_once()
        mock_file().write.assert_called_once_with('{\n  "key": "value"\n}')

def test_save_report_content_file_system_error(mock_workbench):
    # Test handling of file system errors
    response = MagicMock(spec=requests.Response)
    response.content = b"Test content"
    response.headers = {"content-type": "text/plain"}
    response.encoding = "utf-8"
    
    with patch("builtins.open", mock_open()) as mock_file:
        mock_file.side_effect = IOError("File system error")
        with pytest.raises(FileSystemError, match="Failed to write report to"):
            _save_report_content(response, "output_dir", "scan", "test_scan", "basic")

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
    filepath = "output/results.json"
    results = {"key": "value"}
    scan_code = "TEST_SCAN"
    _save_results_to_file(filepath, results, scan_code)
    mock_makedirs.assert_called_once_with("output", exist_ok=True)
    # Check file was opened for writing
    mock_open_file.assert_any_call(filepath, 'w', encoding='utf-8')
    # Join all write calls to get the full written content
    handle = mock_open_file()
    written = "".join(call_arg[0][0] for call_arg in handle.write.call_args_list)
    assert json.loads(written) == results

@patch("os.makedirs", side_effect=OSError("Cannot create dir"))
def test_save_results_to_file_makedirs_error(mock_makedirs):
    filepath = "output/results.json"
    results = {"key": "value"}
    scan_code = "TEST_SCAN"
    _save_results_to_file(filepath, results, scan_code)
    mock_makedirs.assert_called_once_with("output", exist_ok=True)
    # No file open should be attempted if makedirs fails

@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_save_results_to_file_write_error(mock_makedirs, mock_open_file):
    filepath = "output/results.json"
    results = {"key": "value"}
    scan_code = "TEST_SCAN"
    # Simulate write error
    handle = mock_open_file()
    handle.write.side_effect = IOError("Cannot write file")
    _save_results_to_file(filepath, results, scan_code)
    mock_makedirs.assert_called_once_with("output", exist_ok=True)
    mock_open_file.assert_any_call(filepath, 'w', encoding='utf-8')
    # The write will fail, but the function should handle/log the error

