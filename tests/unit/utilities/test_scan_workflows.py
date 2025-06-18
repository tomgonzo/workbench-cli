import pytest
import argparse
import time
import json
import os
import requests
from unittest.mock import MagicMock, patch, mock_open, call
from typing import Dict, Any

from workbench_cli.utilities.scan_workflows import (
    assert_scan_is_idle,
    wait_for_scan_completion,
    determine_scans_to_run,
    fetch_results,
    display_results,
    save_results_to_file,
    fetch_display_save_results,
    format_duration,
    print_operation_summary,
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

# --- Fixtures ---
@pytest.fixture
def mock_workbench(mocker):
    workbench = mocker.MagicMock()
    workbench.list_projects.return_value = [
        {"name": "test_project", "code": "TEST_PROJECT", "project_name": "test_project", "project_code": "TEST_PROJECT"}
    ]
    workbench.get_project_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123", "project_code": "TEST_PROJECT"}
    ]
    workbench.list_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    workbench.assert_process_can_start = mocker.MagicMock(return_value=None)
    workbench.get_scan_status = mocker.MagicMock()
    workbench.check_status_download_content_from_git = mocker.MagicMock()
    workbench._is_status_check_supported = mocker.MagicMock()
    workbench._standard_scan_status_accessor = mocker.MagicMock()
    workbench.wait_for_git_clone = mocker.MagicMock()
    workbench.wait_for_archive_extraction = mocker.MagicMock()
    workbench.wait_for_scan_to_finish = mocker.MagicMock()
    workbench.get_dependency_analysis_results = mocker.MagicMock()
    workbench.list_vulnerabilities = mocker.MagicMock()
    workbench.get_scan_identified_licenses = mocker.MagicMock()
    workbench.get_scan_identified_components = mocker.MagicMock()
    workbench.get_scan_folder_metrics = mocker.MagicMock()
    workbench.get_policy_warnings_counter = mocker.MagicMock()
    return workbench

@pytest.fixture
def mock_params(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    params.command = None
    params.project_name = None
    params.scan_name = None
    params.git_url = None
    params.git_branch = None
    params.git_tag = None
    params.git_depth = None
    params.id_reuse = False
    params.id_reuse_type = None
    params.id_reuse_source = None
    params.show_licenses = False
    params.show_components = False
    params.show_dependencies = False
    params.show_scan_metrics = False
    params.show_policy_warnings = False
    params.show_vulnerabilities = False
    params.path_result = None
    params.run_dependency_analysis = False
    params.dependency_analysis_only = False
    return params

# --- Tests for format_duration (migrated from old test_utils.py) ---
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

# --- Tests for save_results_to_file (migrated from old test_utils.py) ---
@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_save_results_to_file_success(mock_makedirs, mock_open_file):
    filepath = "output/results.json"
    results = {"key": "value"}
    scan_code = "TEST_SCAN"
    save_results_to_file(filepath, results, scan_code)
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
    save_results_to_file(filepath, results, scan_code)
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
    save_results_to_file(filepath, results, scan_code)
    mock_makedirs.assert_called_once_with("output", exist_ok=True)
    mock_open_file.assert_any_call(filepath, 'w', encoding='utf-8')
    # The write will fail, but the function should handle/log the error

# --- Tests for assert_scan_is_idle ---
def test_assert_scan_is_idle_all_idle(mock_workbench, mock_params):
    """Test when all processes are already idle."""
    mock_workbench.check_status_download_content_from_git.return_value = "FINISHED"
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench._standard_scan_status_accessor.return_value = "FINISHED"
    
    # Should not raise and should check statuses
    assert_scan_is_idle(mock_workbench, "TEST_SCAN", mock_params, ["GIT_CLONE", "SCAN"])
    
    mock_workbench.check_status_download_content_from_git.assert_called_with("TEST_SCAN")
    mock_workbench.get_scan_status.assert_called_with("SCAN", "TEST_SCAN")

def test_assert_scan_is_idle_scan_not_found(mock_workbench, mock_params):
    """Test when scan is not found during idle check."""
    mock_workbench.check_status_download_content_from_git.side_effect = ScanNotFoundError("Not found")
    
    # Should not raise and should handle gracefully
    assert_scan_is_idle(mock_workbench, "TEST_SCAN", mock_params, ["GIT_CLONE"])

def test_assert_scan_is_idle_api_error(mock_workbench, mock_params):
    """Test API error during idle check."""
    mock_workbench.check_status_download_content_from_git.side_effect = ApiError("API Error")
    
    with pytest.raises(ProcessError, match="Failed to check status"):
        assert_scan_is_idle(mock_workbench, "TEST_SCAN", mock_params, ["GIT_CLONE"])

def test_assert_scan_is_idle_extract_archives_not_supported(mock_workbench, mock_params):
    """Test extract archives when status checking is not supported."""
    mock_workbench._is_status_check_supported.return_value = False
    
    # Should complete without errors
    assert_scan_is_idle(mock_workbench, "TEST_SCAN", mock_params, ["EXTRACT_ARCHIVES"])
    
    mock_workbench._is_status_check_supported.assert_called_with("TEST_SCAN", "EXTRACT_ARCHIVES")

# --- Tests for wait_for_scan_completion ---
def test_wait_for_scan_completion_both_finished(mock_workbench, mock_params):
    """Test when both KB scan and DA are already finished."""
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench._standard_scan_status_accessor.return_value = "FINISHED"
    
    scan_completed, da_completed, durations = wait_for_scan_completion(mock_workbench, mock_params, "TEST_SCAN")
    
    assert scan_completed is True
    assert da_completed is True
    assert "kb_scan" in durations
    assert "dependency_analysis" in durations

def test_wait_for_scan_completion_kb_scan_failed(mock_workbench, mock_params):
    """Test when KB scan has failed."""
    mock_workbench.get_scan_status.return_value = {"status": "FAILED"}
    mock_workbench._standard_scan_status_accessor.return_value = "FAILED"
    
    scan_completed, da_completed, durations = wait_for_scan_completion(mock_workbench, mock_params, "TEST_SCAN")
    
    assert scan_completed is False
    assert da_completed is False

def test_wait_for_scan_completion_da_new(mock_workbench, mock_params):
    """Test when DA has not been run (status = NEW)."""
    mock_workbench.get_scan_status.side_effect = [
        {"status": "FINISHED"},  # KB scan
        {"status": "NEW"}        # DA
    ]
    mock_workbench._standard_scan_status_accessor.side_effect = ["FINISHED", "NEW"]
    
    scan_completed, da_completed, durations = wait_for_scan_completion(mock_workbench, mock_params, "TEST_SCAN")
    
    assert scan_completed is True
    assert da_completed is False

# --- Tests for determine_scans_to_run ---
def test_determine_scans_to_run_default(mock_params):
    """Test default behavior - only KB scan."""
    mock_params.run_dependency_analysis = False
    mock_params.dependency_analysis_only = False
    
    result = determine_scans_to_run(mock_params)
    
    assert result == {"run_kb_scan": True, "run_dependency_analysis": False}

def test_determine_scans_to_run_with_da(mock_params):
    """Test with dependency analysis enabled."""
    mock_params.run_dependency_analysis = True
    mock_params.dependency_analysis_only = False
    
    result = determine_scans_to_run(mock_params)
    
    assert result == {"run_kb_scan": True, "run_dependency_analysis": True}

def test_determine_scans_to_run_da_only(mock_params):
    """Test with dependency analysis only."""
    mock_params.run_dependency_analysis = False
    mock_params.dependency_analysis_only = True
    
    result = determine_scans_to_run(mock_params)
    
    assert result == {"run_kb_scan": False, "run_dependency_analysis": True}

def test_determine_scans_to_run_both_flags(mock_params):
    """Test with both DA flags - should use DA only."""
    mock_params.run_dependency_analysis = True
    mock_params.dependency_analysis_only = True
    
    result = determine_scans_to_run(mock_params)
    
    assert result == {"run_kb_scan": False, "run_dependency_analysis": True}

# --- Tests for fetch_results ---
def test_fetch_results_no_flags(mock_workbench, mock_params):
    """Test when no result flags are set."""
    result = fetch_results(mock_workbench, mock_params, "TEST_SCAN")
    
    assert result == {}

def test_fetch_results_licenses(mock_workbench, mock_params):
    """Test fetching license results."""
    mock_params.show_licenses = True
    mock_workbench.get_dependency_analysis_results.return_value = {"licenses": ["MIT", "GPL"]}
    
    result = fetch_results(mock_workbench, mock_params, "TEST_SCAN")
    
    assert "dependency_analysis" in result
    mock_workbench.get_dependency_analysis_results.assert_called_once_with("TEST_SCAN")

def test_fetch_results_vulnerabilities(mock_workbench, mock_params):
    """Test fetching vulnerability results."""
    mock_params.show_vulnerabilities = True
    mock_workbench.list_vulnerabilities.return_value = [{"cve": "CVE-2021-1234"}]
    
    result = fetch_results(mock_workbench, mock_params, "TEST_SCAN")
    
    assert "vulnerabilities" in result
    mock_workbench.list_vulnerabilities.assert_called_once_with("TEST_SCAN")

def test_fetch_results_api_error(mock_workbench, mock_params):
    """Test handling API errors during result fetching."""
    mock_params.show_licenses = True
    mock_workbench.get_dependency_analysis_results.side_effect = ApiError("API Error")
    mock_workbench.get_scan_identified_licenses.return_value = [{"identifier": "MIT", "name": "MIT License"}]
    
    # Should not raise, should return partial results
    result = fetch_results(mock_workbench, mock_params, "TEST_SCAN")
    
    # Should return kb_licenses since that call succeeded
    assert "kb_licenses" in result

# --- Tests for display_results ---
def test_display_results_empty(mock_params):
    """Test displaying empty results."""
    result = display_results({}, mock_params)
    assert result is False  # No results to display

def test_display_results_with_data(mock_params):
    """Test displaying results with data."""
    # Need to set the appropriate flags for the data to be displayed
    mock_params.show_dependencies = True
    mock_params.show_vulnerabilities = True
    results = {
        "dependency_analysis": [{"name": "test", "version": "1.0", "license_identifier": "MIT"}],
        "vulnerabilities": [{"cve": "CVE-2021-1234", "severity": "HIGH", "component_name": "test", "component_version": "1.0"}]
    }
    
    result = display_results(results, mock_params)
    assert result is True

# --- Tests for fetch_display_save_results ---
@patch('workbench_cli.utilities.scan_workflows.fetch_results')
@patch('workbench_cli.utilities.scan_workflows.display_results')
@patch('workbench_cli.utilities.scan_workflows.save_results_to_file')
def test_fetch_display_save_results_complete(mock_save, mock_display, mock_fetch, mock_workbench, mock_params):
    """Test complete fetch, display, and save workflow."""
    mock_params.path_result = "output.json"
    mock_params.show_licenses = True  # Need at least one flag set for display
    mock_fetch.return_value = {"test": "data"}
    mock_display.return_value = True
    
    fetch_display_save_results(mock_workbench, mock_params, "TEST_SCAN")
    
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "TEST_SCAN")
    mock_display.assert_called_once_with({"test": "data"}, mock_params)
    mock_save.assert_called_once_with("output.json", {"test": "data"}, "TEST_SCAN")

@patch('workbench_cli.utilities.scan_workflows.fetch_results')
@patch('workbench_cli.utilities.scan_workflows.display_results')
def test_fetch_display_save_results_no_save(mock_display, mock_fetch, mock_workbench, mock_params):
    """Test fetch and display without saving."""
    mock_params.path_result = None
    mock_params.show_licenses = True  # Need at least one flag set for display
    mock_fetch.return_value = {"test": "data"}
    mock_display.return_value = True
    
    fetch_display_save_results(mock_workbench, mock_params, "TEST_SCAN")
    
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "TEST_SCAN")
    mock_display.assert_called_once_with({"test": "data"}, mock_params)

# --- Tests for print_operation_summary ---
def test_print_operation_summary_basic(mock_params):
    """Test basic operation summary."""
    mock_params.command = "scan"
    
    print_operation_summary(mock_params, True, "PROJ_CODE", "SCAN_CODE")
    # Should complete without errors

def test_print_operation_summary_with_durations(mock_params):
    """Test operation summary with timing information."""
    mock_params.command = "scan"
    durations = {"kb_scan": 120.5, "dependency_analysis": 60.0}
    
    print_operation_summary(mock_params, True, "PROJ_CODE", "SCAN_CODE", durations)
    # Should complete without errors

def test_print_operation_summary_da_failed(mock_params):
    """Test operation summary when DA failed."""
    mock_params.command = "scan"
    
    print_operation_summary(mock_params, False, "PROJ_CODE", "SCAN_CODE")
    # Should complete without errors 