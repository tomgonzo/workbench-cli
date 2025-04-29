# tests/handlers/test_scan_handler.py

import pytest
from unittest.mock import MagicMock, patch
import time # For mocking sleep

# Import handler and dependencies
from workbench_agent import handlers
from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ProjectNotFoundError,
    ScanNotFoundError
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers.Workbench._is_status_check_supported', return_value=True) # Assume supported
@patch('workbench_agent.handlers.Workbench.wait_for_archive_extraction')
@patch('workbench_agent.handlers._execute_standard_scan_flow') # Mock the whole flow utility
def test_handle_scan_success(mock_exec_flow, mock_wait_extract, mock_is_supported, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'scan'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "/path"
    mock_params.recursively_extract_archives = True; mock_params.jar_file_extraction = False
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_extract.return_value = True # Simulate extraction triggered

    handlers.handle_scan(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once_with(mock_workbench, "P", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name="S", project_name="P", create_if_missing=True, params=mock_params)
    mock_upload.assert_called_once_with("SC", "/path", is_da_import=False)
    mock_extract.assert_called_once_with("SC", True, False)
    mock_is_supported.assert_called_once_with("SC", "EXTRACT_ARCHIVES")
    mock_wait_extract.assert_called_once()
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "PC", "SC", 1)

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers.Workbench._is_status_check_supported', return_value=False) # Assume NOT supported
@patch('workbench_agent.handlers.Workbench.wait_for_archive_extraction')
@patch('workbench_agent.handlers._execute_standard_scan_flow')
@patch('time.sleep', return_value=None) # Mock sleep
def test_handle_scan_success_no_extract_wait(mock_sleep, mock_exec_flow, mock_wait_extract, mock_is_supported, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'scan'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "/path"
    mock_params.recursively_extract_archives = True; mock_params.jar_file_extraction = False
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_extract.return_value = True

    handlers.handle_scan(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_extract.assert_called_once()
    mock_is_supported.assert_called_once_with("SC", "EXTRACT_ARCHIVES")
    mock_wait_extract.assert_not_called() # Wait should NOT be called
    mock_sleep.assert_called_once_with(10) # Sleep should be called
    mock_exec_flow.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files', side_effect=FileSystemError("Upload Failed"))
@patch('workbench_agent.handlers.Workbench.extract_archives') # Need to patch subsequent calls too
@patch('workbench_agent.handlers._execute_standard_scan_flow')
def test_handle_scan_upload_fails(mock_exec_flow, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'scan'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "/path"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(FileSystemError, match="Upload Failed"):
        handlers.handle_scan(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    # Assert subsequent functions were NOT called
    mock_extract.assert_not_called()
    mock_exec_flow.assert_not_called()

@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("Project not found"))
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
def test_handle_scan_project_not_found(mock_upload, mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    mock_params.command = 'scan'
    with pytest.raises(ProjectNotFoundError):
        handlers.handle_scan(mock_workbench, mock_params)
    mock_resolve_project.assert_called_once()
    mock_resolve_scan.assert_not_called()
    mock_upload.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("Scan not found"))
@patch('workbench_agent.handlers.Workbench.upload_files')
def test_handle_scan_scan_not_found(mock_upload, mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    mock_params.command = 'scan'
    mock_resolve_project.return_value = "TEST_PROJECT"
    with pytest.raises(ScanNotFoundError):
        handlers.handle_scan(mock_workbench, mock_params)
    mock_resolve_project.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=ApiError("API error"))
def test_handle_scan_api_error(mock_execute_flow, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    mock_params.command = 'scan'
    mock_resolve_project.return_value = "TEST_PROJECT"
    mock_resolve_scan.return_value = ("TEST_SCAN", "123")
    mock_extract.return_value = False # Assume no extraction needed for simplicity

    with pytest.raises(ApiError):
        handlers.handle_scan(mock_workbench, mock_params)
    mock_execute_flow.assert_called_once() # Error happens during execution

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=NetworkError("Network error"))
def test_handle_scan_network_error(mock_execute_flow, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    mock_params.command = 'scan'
    mock_resolve_project.return_value = "TEST_PROJECT"
    mock_resolve_scan.return_value = ("TEST_SCAN", "123")
    mock_extract.return_value = False

    with pytest.raises(NetworkError):
        handlers.handle_scan(mock_workbench, mock_params)
    mock_execute_flow.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=ProcessError("Process error"))
def test_handle_scan_process_error(mock_execute_flow, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    mock_params.command = 'scan'
    mock_resolve_project.return_value = "TEST_PROJECT"
    mock_resolve_scan.return_value = ("TEST_SCAN", "123")
    mock_extract.return_value = False

    with pytest.raises(ProcessError):
        handlers.handle_scan(mock_workbench, mock_params)
    mock_execute_flow.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=ProcessTimeoutError("Process timeout"))
def test_handle_scan_process_timeout(mock_execute_flow, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    mock_params.command = 'scan'
    mock_resolve_project.return_value = "TEST_PROJECT"
    mock_resolve_scan.return_value = ("TEST_SCAN", "123")
    mock_extract.return_value = False

    with pytest.raises(ProcessTimeoutError):
        handlers.handle_scan(mock_workbench, mock_params)
    mock_execute_flow.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=Exception("Unexpected error"))
def test_handle_scan_unexpected_error(mock_execute_flow, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_project, mock_workbench, mock_params):
    mock_params.command = 'scan'
    mock_resolve_project.return_value = "TEST_PROJECT"
    mock_resolve_scan.return_value = ("TEST_SCAN", "123")
    mock_extract.return_value = False

    # Expect it to be wrapped in WorkbenchAgentError
    with pytest.raises(WorkbenchAgentError):
        handlers.handle_scan(mock_workbench, mock_params)
    mock_execute_flow.assert_called_once()

