# tests/handlers/test_scan_handler.py

import pytest
import os
from unittest.mock import MagicMock, patch, call
import time # For mocking sleep

# Import handler and dependencies
from workbench_cli.handlers.scan import handle_scan
from workbench_cli.exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ProjectNotFoundError,
    ScanNotFoundError,
    CompatibilityError,
    ValidationError
)
from workbench_cli.utilities.scan_target_validators import ensure_scan_compatibility
from .. import handlers

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

def setup_common_mock_params(mock_params):
    """Helper function to set up common mock parameters for tests."""
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.show_licenses = True
    mock_params.show_components = True
    mock_params.show_vulnerabilities = True
    mock_params.show_dependencies = False
    mock_params.show_scan_metrics = False
    mock_params.show_policy_warnings = False
    mock_params.no_wait = False
    mock_params.output_format = "text"
    mock_params.output_file = None
    return mock_params

@patch('workbench_cli.handlers.scan.fetch_display_save_results')
@patch('workbench_cli.handlers.scan.print_operation_summary')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan.wait_for_scan_completion', return_value=(True, True, {}))
@patch('workbench_cli.handlers.scan.assert_scan_is_idle')
def test_handle_scan_success_kb_and_da(mock_assert_idle, mock_wait, mock_determine_scans, mock_summary, mock_fetch, mock_workbench, mock_params):
    """Tests a successful run of handle_scan with both KB and DA scans."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    
    # Configure mock return values
    mock_workbench.resolve_project.return_value = "PC123"
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    mock_workbench.wait_for_archive_extraction.return_value = ({}, 5.0)
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)
    mock_workbench.run_scan.return_value = None
    mock_workbench.__dict__['assert_process_can_start'] = MagicMock(return_value=None)
    
    # Execute the function
    result = handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once_with("SC456", 10, 5)
    mock_workbench.__dict__['assert_process_can_start'].assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with("SCAN", "SC456", 10, 5)
    mock_determine_scans.assert_called_once_with(mock_params)
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "SC456")
    mock_wait.assert_called_once()
    mock_summary.assert_called_once()
    assert result == True

@patch('workbench_cli.handlers.scan.fetch_display_save_results')
@patch('workbench_cli.handlers.scan.print_operation_summary')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan.wait_for_scan_completion', return_value=(True, False, {}))
@patch('workbench_cli.handlers.scan.assert_scan_is_idle')
def test_handle_scan_success_kb_only(mock_assert_idle, mock_wait, mock_determine_scans, mock_summary, mock_fetch, mock_workbench, mock_params):
    """Tests a successful run of handle_scan with only a KB scan."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    
    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": False}
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    mock_workbench.wait_for_archive_extraction.return_value = ({}, 5.0)
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)
    mock_workbench.run_scan.return_value = None
    
    # Execute the function
    result = handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once_with("SC456", 10, 5)
    mock_workbench.__dict__['assert_process_can_start'].assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with("SCAN", "SC456", 10, 5)
    mock_determine_scans.assert_called_once_with(mock_params)
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "SC456")
    mock_wait.assert_called_once()
    mock_summary.assert_called_once()
    assert result == True

@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_da_only(mock_determine_scans, mock_workbench, mock_params):
    """Tests that run_scan is not called when only DA is requested (which is not a valid scenario for this handler)."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {"run_kb_scan": False, "run_dependency_analysis": True}
    
    # Execute the function with expected exception
    with pytest.raises(ProcessError, match="Process error occurred"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_workbench.upload_files.assert_not_called()
    mock_workbench.extract_archives.assert_not_called()
    mock_workbench.run_scan.assert_not_called()
    mock_determine_scans.assert_called_once_with(mock_params)
    mock_workbench.assert_process_can_start.assert_called_once()

@patch('workbench_cli.handlers.scan.fetch_display_save_results')
@patch('workbench_cli.handlers.scan.print_operation_summary')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan.wait_for_scan_completion')
@patch('workbench_cli.handlers.scan.assert_scan_is_idle')
def test_handle_scan_no_wait(mock_assert_idle, mock_wait, mock_determine_scans, mock_summary, mock_fetch, mock_workbench, mock_params):
    """Tests the --no-wait flag functionality."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    
    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    mock_workbench.wait_for_archive_extraction.return_value = ({}, 5.0)
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)
    mock_workbench.run_scan.return_value = None
    
    # Execute the function
    result = handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once_with("SC456", 10, 5)
    mock_workbench.__dict__['assert_process_can_start'].assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with("SCAN", "SC456", 10, 5)
    mock_determine_scans.assert_called_once_with(mock_params)
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "SC456")
    mock_wait.assert_not_called()
    mock_summary.assert_called_once()
    assert result == True

@patch('os.path.exists', return_value=False)
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
def test_handle_scan_path_not_exists(mock_ensure_compatibility, mock_path_exists, mock_workbench, mock_params):
    """Tests validation error when the provided path doesn't exist."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    mock_params.path = "/nonexistent/path"
    
    # Execute the function with expected exception
    with pytest.raises(FileSystemError, match="does not exist"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/nonexistent/path")
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
def test_handle_scan_project_not_found(mock_assert_idle, mock_path_exists, mock_workbench, mock_params):
    """Tests that ProjectNotFoundError from _resolve_project propagates."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    mock_params.project_name = "NonExistentProject"
    
    # Configure mock to raise ProjectNotFoundError
    mock_workbench.configure_mock(resolve_project=MagicMock(side_effect=ProjectNotFoundError("Project not found")))
    
    # Execute the function with expected exception
    with pytest.raises(ProjectNotFoundError, match="Project not found"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
def test_handle_scan_scan_not_found(mock_assert_idle, mock_path_exists, mock_workbench, mock_params):
    """Tests that ScanNotFoundError from _resolve_scan propagates."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    mock_params.scan_name = "NonExistentScan"
    
    # Configure mock return values
    mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")
    mock_workbench.get_scan_information.return_value = {}
    
    # Execute the function with expected exception
    with pytest.raises(ScanNotFoundError, match="Scan not found"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="NonExistentScan",
        project_name="TestProject",
        create_if_missing=True,
        params=mock_params
    )
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
def test_handle_scan_api_error(mock_assert_idle, mock_path_exists, mock_ensure_compatibility, mock_determine_scans,
                             mock_workbench, mock_params):
    """Tests that ApiError from upload_files propagates."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    
    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock methods to raise ApiError
    mock_workbench.upload_files.side_effect = ApiError("API error occurred")
    
    # Execute the function with expected exception
    with pytest.raises(ApiError, match="API error occurred"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="TestScan",
        project_name="TestProject",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_not_called()
    mock_workbench.assert_process_can_start.assert_not_called()
    mock_workbench.run_scan.assert_not_called()

@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
def test_handle_scan_network_error(mock_assert_idle, mock_path_exists, mock_ensure_compatibility, mock_determine_scans,
                                 mock_workbench, mock_params):
    """Tests that NetworkError from upload_files propagates."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    
    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock methods to raise NetworkError
    mock_workbench.upload_files.side_effect = NetworkError("Network error occurred")
    
    # Execute the function with expected exception
    with pytest.raises(NetworkError, match="Network error occurred"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="TestScan",
        project_name="TestProject",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_not_called()
    mock_workbench.assert_process_can_start.assert_not_called()
    mock_workbench.run_scan.assert_not_called()

@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_process_error(mock_determine_scans, mock_ensure_compatibility, mock_path_exists,
                                 mock_assert_idle, mock_workbench, mock_params):
    """Tests that ProcessError from run_scan propagates."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)

    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}

    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }

    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    mock_workbench.wait_for_archive_extraction.return_value = ({}, 5.0)
    mock_workbench.run_scan.side_effect = ProcessError("Process error occurred")

    # Execute the function with expected exception
    with pytest.raises(ProcessError, match="Process error occurred"):
        handle_scan(mock_workbench, mock_params)

    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="TestScan",
        project_name="TestProject",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once_with("SC456", 10, 5)
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()

@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_process_timeout(mock_determine_scans, mock_ensure_compatibility, mock_path_exists,
                                   mock_assert_idle, mock_workbench, mock_params):
    """Tests that ProcessTimeoutError from wait_for_scan_to_finish propagates."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)

    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}

    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }

    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    mock_workbench.wait_for_archive_extraction.return_value = ({}, 5.0)
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Process timeout occurred")

    # Execute the function with expected exception
    with pytest.raises(ProcessTimeoutError, match="Process timeout occurred"):
        handle_scan(mock_workbench, mock_params)

    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="TestScan",
        project_name="TestProject",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once_with("SC456", 10, 5)
    mock_determine_scans.assert_called_once_with(mock_params)
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with("SCAN", "SC456", 10, 5)

@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan._fetch_display_save_results')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan._print_operation_summary')
def test_handle_scan_extraction_error(mock_print_summary, mock_determine_scans, mock_ensure_compatibility,
                                    mock_path_exists, mock_fetch_results, mock_assert_idle,
                                    mock_workbench, mock_params):
    """Tests handling of archive extraction errors."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)

    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}

    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }

    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    mock_workbench.wait_for_archive_extraction.side_effect = Exception("Extraction error")
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)
    mock_workbench.run_scan.return_value = None

    # Execute the function
    result = handle_scan(mock_workbench, mock_params)

    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="TestScan",
        project_name="TestProject",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once_with("SC456", 10, 5)
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with("SCAN", "SC456", 10, 5)
    mock_determine_scans.assert_called_once_with(mock_params)
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SC456")
    mock_ensure_compatibility.assert_called_once_with(mock_workbench, mock_params, "SC456")
    assert result == True

@patch('workbench_cli.handlers.scan._print_operation_summary')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._fetch_display_save_results')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
def test_handle_scan_success_no_extraction_needed(mock_assert_idle, mock_fetch_results, mock_path_exists,
                                               mock_ensure_compatibility, mock_determine_scans, mock_print_summary,
                                               mock_workbench, mock_params):
    """Tests successful execution when no archive extraction is needed."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    
    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = False
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)
    mock_workbench.run_scan.return_value = None
    
    # Execute the function
    result = handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="TestScan",
        project_name="TestProject",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_not_called()
    mock_workbench.wait_for_archive_extraction.assert_not_called()
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with("SCAN", "SC456", 10, 5)
    mock_determine_scans.assert_called_once_with(mock_params)
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SC456")
    mock_ensure_compatibility.assert_called_once_with(mock_workbench, mock_params, "SC456")
    assert result == True

@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan.ensure_scan_compatibility')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._fetch_display_save_results')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
def test_handle_scan_upload_fails(mock_assert_idle, mock_fetch_results, mock_path_exists,
                                mock_ensure_compatibility, mock_determine_scans,
                                mock_workbench, mock_params):
    """Tests handling of upload failure."""
    # Setup mock parameters
    setup_common_mock_params(mock_params)
    
    # Configure mock return values
    mock_workbench.resolve_scan.return_value = ("SC456", 789)
    mock_workbench.get_scan_information.return_value = {}
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock methods
    mock_workbench.upload_files.side_effect = ApiError("Upload failed")
    
    # Execute the function with expected exception
    with pytest.raises(ApiError, match="Upload failed"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="TestScan",
        project_name="TestProject",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_not_called()
    mock_workbench.run_scan.assert_not_called()
    mock_workbench.assert_process_can_start.assert_not_called()

