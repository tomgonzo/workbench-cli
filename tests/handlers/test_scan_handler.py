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

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan._fetch_display_save_results')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan._print_operation_summary')
def test_handle_scan_success(mock_print_summary, mock_determine_scans, mock_ensure_compatibility, 
                            mock_path_exists, mock_fetch_results, mock_assert_idle, 
                            mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution of handle_scan with archive extraction and status check support."""
    # Setup mock parameters and return values
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
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
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
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Execute the function
    result = handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_resolve_proj.assert_called_once_with(mock_workbench, "TestProject", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, 
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

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan._fetch_display_save_results')
@patch('time.sleep')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan._print_operation_summary')
@patch('workbench_cli.api.WorkbenchAPI.assert_process_can_start')
def test_handle_scan_success_no_extract_wait(mock_assert_process, mock_print_summary, mock_determine_scans, mock_ensure_compatibility, 
                                           mock_path_exists, mock_sleep, mock_fetch_results, 
                                           mock_assert_idle, mock_resolve_scan, 
                                           mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution with archive extraction but no status check support."""
    # Setup mock parameters and return values
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
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = False
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)
    mock_workbench.run_scan.return_value = None
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Execute the function
    result = handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_resolve_proj.assert_called_once_with(mock_workbench, "TestProject", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, 
        scan_name="TestScan", 
        project_name="TestProject", 
        create_if_missing=True, 
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_not_called()
    mock_sleep.assert_called_once()
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once_with("SCAN", "SC456", 10, 5)
    mock_determine_scans.assert_called_once_with(mock_params)
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SC456")
    mock_ensure_compatibility.assert_called_once_with(mock_workbench, mock_params, "SC456")
    assert result == True

@patch('os.path.exists', return_value=False)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
def test_handle_scan_path_not_exists(mock_ensure_compatibility, mock_path_exists, mock_workbench, mock_params):
    """Tests validation error when the provided path doesn't exist."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/nonexistent/path"
    
    # Execute the function with expected exception
    with pytest.raises(FileSystemError, match="does not exist"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/nonexistent/path")
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_cli.handlers.scan._resolve_project', side_effect=ProjectNotFoundError("Project not found"))
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
def test_handle_scan_project_not_found(mock_ensure_compatibility, mock_path_exists, mock_resolve_project, 
                                     mock_workbench, mock_params):
    """Tests that ProjectNotFoundError from _resolve_project propagates."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "NonExistentProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    
    # Execute the function with expected exception
    with pytest.raises(ProjectNotFoundError, match="Project not found"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_resolve_project.assert_called_once_with(mock_workbench, "NonExistentProject", create_if_missing=True)
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan', side_effect=ScanNotFoundError("Scan not found"))
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
def test_handle_scan_scan_not_found(mock_ensure_compatibility, mock_path_exists, mock_resolve_scan, mock_resolve_project, 
                                  mock_workbench, mock_params):
    """Tests that ScanNotFoundError from _resolve_scan propagates."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "NonExistentScan"
    mock_params.path = "/test/path"
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    
    # Execute the function with expected exception
    with pytest.raises(ScanNotFoundError, match="Scan not found"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_resolve_project.assert_called_once_with(mock_workbench, "TestProject", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, 
        scan_name="NonExistentScan", 
        project_name="TestProject", 
        create_if_missing=True, 
        params=mock_params
    )

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_api_error(mock_determine_scans, mock_ensure_compatibility, mock_path_exists, 
                             mock_assert_idle, mock_resolve_scan, mock_resolve_project, 
                             mock_workbench, mock_params):
    """Tests API error during the scan process."""
    # Setup mock parameters
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
    mock_params.output_format = "text"
    mock_params.output_file = None
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure extract_archives to return False
    mock_workbench.extract_archives.return_value = False
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Set up API error
    mock_workbench.run_scan.side_effect = ApiError("API error during scan")
    
    # Execute with expected exception
    with pytest.raises(ApiError, match="API error during scan"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once()
    mock_workbench.run_scan.assert_called_once()

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_network_error(mock_determine_scans, mock_ensure_compatibility, mock_path_exists, 
                                 mock_assert_idle, mock_resolve_scan, mock_resolve_project, 
                                 mock_workbench, mock_params):
    """Tests network error during the scan process."""
    # Setup mock parameters
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
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure extract_archives to return False
    mock_workbench.extract_archives.return_value = False
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Set up Network error
    mock_workbench.run_scan.side_effect = NetworkError("Network error during scan")
    
    # Execute with expected exception
    with pytest.raises(NetworkError, match="Network error during scan"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once()
    mock_workbench.run_scan.assert_called_once()

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_process_error(mock_determine_scans, mock_ensure_compatibility, mock_path_exists, 
                                 mock_assert_idle, mock_resolve_scan, mock_resolve_project, 
                                 mock_workbench, mock_params):
    """Tests process error during the scan process."""
    # Setup mock parameters
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
    mock_params.output_format = "text"
    mock_params.output_file = None
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure extract_archives to return False
    mock_workbench.extract_archives.return_value = False
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Set up Process error - occurs during wait_for_scan_to_finish
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessError("Process error during scan")
    
    # Execute with expected exception
    with pytest.raises(ProcessError, match="Process error during scan"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_process_timeout(mock_determine_scans, mock_ensure_compatibility, mock_path_exists, 
                                   mock_assert_idle, mock_resolve_scan, mock_resolve_project, 
                                   mock_workbench, mock_params):
    """Tests process timeout during the scan process."""
    # Setup mock parameters
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
    mock_params.output_format = "text"
    mock_params.output_file = None
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure extract_archives to return False
    mock_workbench.extract_archives.return_value = False
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Set up Process timeout error - occurs during wait_for_scan_to_finish
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Process timeout during scan")
    
    # Execute with expected exception
    with pytest.raises(ProcessTimeoutError, match="Process timeout during scan"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_unexpected_error(mock_determine_scans, mock_ensure_compatibility, mock_path_exists, 
                                    mock_assert_idle, mock_resolve_scan, mock_resolve_project, 
                                    mock_workbench, mock_params):
    """Tests unexpected error handling during the scan process."""
    # Setup mock parameters
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
    mock_params.output_format = "text"
    mock_params.output_file = None
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure extract_archives to return False
    mock_workbench.extract_archives.return_value = False
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Set up unexpected error - the handler_error_wrapper will convert this to a WorkbenchCLIError
    mock_workbench.run_scan.side_effect = Exception("Unexpected error during scan")
    
    # Execute with expected exception - should be wrapped by handler_error_wrapper
    with pytest.raises(WorkbenchCLIError):
        handle_scan(mock_workbench, mock_params)
    
    # Verify calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once()
    mock_workbench.run_scan.assert_called_once()

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
def test_handle_scan_extraction_error(mock_determine_scans, mock_ensure_compatibility, mock_path_exists, 
                                    mock_assert_idle, mock_resolve_scan, mock_resolve_project, 
                                    mock_workbench, mock_params):
    """Tests error handling during the archive extraction phase."""
    # Setup mock parameters
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
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock - extraction enabled but fails during waiting
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    mock_workbench.wait_for_archive_extraction.side_effect = ProcessError("Extraction failed")
    
    # Add wait_for_scan_to_finish return value to avoid error after extraction
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Since the handler code catches the extraction error and continues,
    # verify the code completes the scan despite the extraction error
    result = handle_scan(mock_workbench, mock_params)
    assert result == True
    
    # Verify the extraction_error was caught correctly
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once_with("SC456", 10, 5)
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan._fetch_display_save_results')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.handlers.scan._print_operation_summary')
def test_handle_scan_success_no_extraction_needed(mock_print_summary, mock_determine_scans, mock_ensure_compatibility, 
                                               mock_path_exists, mock_fetch_results, 
                                               mock_assert_idle, mock_resolve_scan, 
                                               mock_resolve_project, mock_workbench, mock_params):
    """Tests successful execution of handle_scan with no archive extraction needed."""
    # Setup mock parameters and return values
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
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)
    mock_workbench.run_scan.return_value = None
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Execute the function
    result = handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_resolve_project.assert_called_once_with(mock_workbench, "TestProject", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, 
        scan_name="TestScan", 
        project_name="TestProject", 
        create_if_missing=True, 
        params=mock_params
    )
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_not_called()  # No need to check status
    mock_workbench.wait_for_archive_extraction.assert_not_called()  # No extraction to wait for
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SC456")
    mock_ensure_compatibility.assert_called_once_with(mock_workbench, mock_params, "SC456")
    assert result == True

@patch('workbench_cli.handlers.scan._resolve_project')
@patch('workbench_cli.handlers.scan._resolve_scan')
@patch('workbench_cli.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
@patch('workbench_cli.handlers.scan._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan.determine_scans_to_run')
@patch('workbench_cli.api.WorkbenchAPI.assert_process_can_start')
def test_handle_scan_upload_fails(mock_assert_process, mock_determine_scans, mock_ensure_compatibility, mock_path_exists, 
                                mock_assert_idle, mock_resolve_scan, mock_resolve_proj, 
                                mock_workbench, mock_params):
    """Tests handling of upload failures."""
    # Setup mock parameters
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
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock assert_process_can_start to avoid unittest.mock restrictions on assert* method names
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    
    # Configure upload to fail
    mock_workbench.upload_files.side_effect = ApiError("Upload failed: Invalid response from server")
    
    # Execute with expected exception - should propagate ApiError directly
    with pytest.raises(ApiError, match="Upload failed"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_resolve_proj.assert_called_once_with(mock_workbench, "TestProject", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, 
        scan_name="TestScan", 
        project_name="TestProject", 
        create_if_missing=True, 
        params=mock_params
    )
    mock_assert_idle.assert_called_once()
    mock_workbench.upload_files.assert_called_once()
    mock_workbench.extract_archives.assert_not_called()
    mock_workbench.run_scan.assert_not_called()
    mock_ensure_compatibility.assert_called_once_with(mock_workbench, mock_params, "SC456")

