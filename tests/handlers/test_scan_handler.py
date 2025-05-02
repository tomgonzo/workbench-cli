# tests/handlers/test_scan_handler.py

import pytest
import os
from unittest.mock import MagicMock, patch, call
import time # For mocking sleep

# Import handler and dependencies
from workbench_agent.handlers.scan import handle_scan
from workbench_agent.exceptions import (
    WorkbenchAgentError,
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

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow')
@patch('workbench_agent.handlers.scan._fetch_display_save_results')
@patch('os.path.exists', return_value=True)
def test_handle_scan_success(mock_path_exists, mock_fetch_results, mock_exec_flow, mock_assert_idle, 
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
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    mock_exec_flow.return_value = (True, False, {"kb_scan": 120.5, "dependency_analysis": 0})
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    
    # Execute the function
    handle_scan(mock_workbench, mock_params)
    
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
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "PC123", "SC456", 789)
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SC456")

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow')
@patch('workbench_agent.handlers.scan._fetch_display_save_results')
@patch('time.sleep')
@patch('os.path.exists', return_value=True)
def test_handle_scan_success_no_extract_wait(mock_path_exists, mock_sleep, mock_fetch_results, 
                                           mock_exec_flow, mock_assert_idle, mock_resolve_scan, 
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
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    mock_exec_flow.return_value = (True, False, {"kb_scan": 120.5, "dependency_analysis": 0})
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = False
    
    # Execute the function
    handle_scan(mock_workbench, mock_params)
    
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
    mock_sleep.assert_called_once_with(5)
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "PC123", "SC456", 789)
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SC456")

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow')
@patch('workbench_agent.handlers.scan._fetch_display_save_results')
@patch('os.path.exists', return_value=True)
def test_handle_scan_success_no_extraction_needed(mock_path_exists, mock_fetch_results, 
                                                mock_exec_flow, mock_assert_idle, mock_resolve_scan, 
                                                mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution when no archive extraction is needed."""
    # Setup mock parameters and return values
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    mock_exec_flow.return_value = (True, False, {"kb_scan": 120.5, "dependency_analysis": 0})
    
    # Configure Workbench mock methods - no extraction needed
    mock_workbench.extract_archives.return_value = False
    
    # Execute the function
    handle_scan(mock_workbench, mock_params)
    
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
    # Should not check status or wait when extraction returns False
    mock_workbench._is_status_check_supported.assert_not_called()
    mock_workbench.wait_for_archive_extraction.assert_not_called()
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "PC123", "SC456", 789)
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SC456")

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
def test_handle_scan_upload_fails(mock_path_exists, mock_assert_idle, mock_resolve_scan, 
                                mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure during the file upload process."""
    # Setup mock parameters and return values
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Make upload_files fail with a FileSystemError
    mock_workbench.upload_files.side_effect = FileSystemError("Upload Failed")
    
    # Execute the function with expected exception
    with pytest.raises(FileSystemError, match="Upload Failed"):
        handle_scan(mock_workbench, mock_params)
    
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
    mock_workbench.extract_archives.assert_not_called()

@patch('os.path.exists', return_value=False)
def test_handle_scan_path_not_exists(mock_path_exists, mock_workbench, mock_params):
    """Tests validation error when the provided path doesn't exist."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/nonexistent/path"
    
    # Execute the function with expected exception
    with pytest.raises(FileSystemError, match="The provided path does not exist"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_path_exists.assert_called_once_with("/nonexistent/path")
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_agent.handlers.scan._resolve_project', side_effect=ProjectNotFoundError("Project not found"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_project_not_found(mock_path_exists, mock_resolve_project, mock_workbench, mock_params):
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

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan', side_effect=ScanNotFoundError("Scan not found"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_scan_not_found(mock_path_exists, mock_resolve_scan, mock_resolve_project, 
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
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=ApiError("API error"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_api_error(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                             mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    """Tests that ApiError from _execute_standard_scan_flow propagates."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception
    with pytest.raises(ApiError, match="API error"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
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
    mock_execute_flow.assert_called_once_with(mock_workbench, mock_params, "PC123", "SC456", 789)

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=NetworkError("Network error"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_network_error(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                                 mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    """Tests that NetworkError from _execute_standard_scan_flow propagates."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception
    with pytest.raises(NetworkError, match="Network error"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_execute_flow.assert_called_once_with(mock_workbench, mock_params, "PC123", "SC456", 789)

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=ProcessError("Process error"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_process_error(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                                 mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    """Tests that ProcessError from _execute_standard_scan_flow propagates."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception
    with pytest.raises(ProcessError, match="Process error"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_execute_flow.assert_called_once_with(mock_workbench, mock_params, "PC123", "SC456", 789)

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=ProcessTimeoutError("Process timeout"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_process_timeout(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                                   mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    """Tests that ProcessTimeoutError from _execute_standard_scan_flow propagates."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception
    with pytest.raises(ProcessTimeoutError, match="Process timeout"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_execute_flow.assert_called_once_with(mock_workbench, mock_params, "PC123", "SC456", 789)

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=Exception("Unexpected error"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_unexpected_error(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                                    mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    """Tests that unexpected errors are wrapped in WorkbenchAgentError."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception - should be wrapped
    with pytest.raises(WorkbenchAgentError, match="Unexpected error"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_execute_flow.assert_called_once_with(mock_workbench, mock_params, "PC123", "SC456", 789)

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
def test_handle_scan_extraction_error(mock_path_exists, mock_assert_idle, mock_resolve_scan, 
                                     mock_resolve_project, mock_workbench, mock_params):
    """Tests error handling during the archive extraction phase."""
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "TestProject"
    mock_params.scan_name = "TestScan"
    mock_params.path = "/test/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC123"
    mock_resolve_scan.return_value = ("SC456", 789)
    
    # Configure extraction error
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    mock_workbench.wait_for_archive_extraction.side_effect = ProcessTimeoutError("Extraction timed out")
    
    # Execute the function with expected exception
    with pytest.raises(ProcessTimeoutError, match="Extraction timed out"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_path_exists.assert_called_once_with("/test/path")
    mock_assert_idle.assert_called_once_with(mock_workbench, "SC456", mock_params, ["SCAN", "DEPENDENCY_ANALYSIS"])
    mock_workbench.upload_files.assert_called_once_with("SC456", "/test/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC456", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC456", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once_with("SC456", 10, 5)

