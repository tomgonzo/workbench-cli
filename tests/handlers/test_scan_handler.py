# tests/handlers/test_scan_handler.py

import pytest
import os
from unittest.mock import MagicMock, patch
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
    CompatibilityError
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
    # Setup mock parameters and return values
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    mock_params.scan_number_of_tries = 10

    # Configure mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_exec_flow.return_value = (True, False, {"kb_scan": 120.5, "dependency_analysis": 0})
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = True
    
    # Execute the function
    handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_resolve_proj.assert_called_once_with(mock_workbench, "P", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name="S", project_name="P", create_if_missing=True, params=mock_params)
    mock_assert_idle.assert_called_once()
    mock_workbench.upload_files.assert_called_once_with("SC", "/path", is_da_import=False)
    mock_workbench.extract_archives.assert_called_once_with("SC", True, False)
    mock_workbench._is_status_check_supported.assert_called_once_with("SC", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_called_once()
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "PC", "SC", 1)
    mock_fetch_results.assert_called_once()

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
    # Setup mock parameters and return values
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    mock_params.recursively_extract_archives = True
    mock_params.jar_file_extraction = False
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_exec_flow.return_value = (True, False, {"kb_scan": 120.5, "dependency_analysis": 0})
    
    # Configure Workbench mock methods
    mock_workbench.extract_archives.return_value = True
    mock_workbench._is_status_check_supported.return_value = False
    
    # Execute the function
    handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.upload_files.assert_called_once()
    mock_workbench.extract_archives.assert_called_once()
    mock_workbench._is_status_check_supported.assert_called_once_with("SC", "EXTRACT_ARCHIVES")
    mock_workbench.wait_for_archive_extraction.assert_not_called()
    mock_sleep.assert_called_once_with(5)
    mock_exec_flow.assert_called_once()
    mock_fetch_results.assert_called_once()

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('os.path.exists', return_value=True)
def test_handle_scan_upload_fails(mock_path_exists, mock_assert_idle, mock_resolve_scan, 
                                mock_resolve_proj, mock_workbench, mock_params):
    # Setup mock parameters and return values
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    
    # Configure mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Make upload_files fail with a FileSystemError
    mock_workbench.upload_files.side_effect = FileSystemError("Upload Failed")
    
    # Execute the function with expected exception
    with pytest.raises(FileSystemError, match="Upload Failed"):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.upload_files.assert_called_once()

@patch('workbench_agent.handlers.scan._resolve_project', side_effect=ProjectNotFoundError("Project not found"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_project_not_found(mock_path_exists, mock_resolve_project, mock_workbench, mock_params):
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.path = "/path"
    
    # Execute the function with expected exception
    with pytest.raises(ProjectNotFoundError):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_resolve_project.assert_called_once()
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan', side_effect=ScanNotFoundError("Scan not found"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_scan_not_found(mock_path_exists, mock_resolve_scan, mock_resolve_project, 
                                  mock_workbench, mock_params):
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC"
    
    # Execute the function with expected exception
    with pytest.raises(ScanNotFoundError):
        handle_scan(mock_workbench, mock_params)
    
    # Verify the expected function calls
    mock_resolve_project.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_workbench.upload_files.assert_not_called()

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=ApiError("API error"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_api_error(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                             mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception
    with pytest.raises(ApiError):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_assert_idle.assert_called_once()
    mock_execute_flow.assert_called_once()

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=NetworkError("Network error"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_network_error(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                                 mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception
    with pytest.raises(NetworkError):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_assert_idle.assert_called_once()
    mock_execute_flow.assert_called_once()

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=ProcessError("Process error"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_process_error(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                                 mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception
    with pytest.raises(ProcessError):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_assert_idle.assert_called_once()
    mock_execute_flow.assert_called_once()

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=ProcessTimeoutError("Process timeout"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_process_timeout(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                                   mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception
    with pytest.raises(ProcessTimeoutError):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_assert_idle.assert_called_once()
    mock_execute_flow.assert_called_once()

@patch('workbench_agent.handlers.scan._resolve_project')
@patch('workbench_agent.handlers.scan._resolve_scan')
@patch('workbench_agent.handlers.scan._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan._execute_standard_scan_flow', side_effect=Exception("Unexpected error"))
@patch('os.path.exists', return_value=True)
def test_handle_scan_unexpected_error(mock_path_exists, mock_execute_flow, mock_assert_idle, 
                                    mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    # Setup mock parameters
    mock_params.command = 'scan'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path"
    
    # Configure mock return values
    mock_resolve_project.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_workbench.extract_archives.return_value = False  # No extraction needed
    
    # Execute the function with expected exception - should be wrapped
    with pytest.raises(WorkbenchAgentError):
        handle_scan(mock_workbench, mock_params)
    
    # Verify expected function calls
    mock_assert_idle.assert_called_once()
    mock_execute_flow.assert_called_once()

