# tests/handlers/test_import_da_handler.py

import pytest
from unittest.mock import MagicMock, patch

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
    ScanNotFoundError,
    CompatibilityError
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.start_dependency_analysis') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers._print_operation_summary') # Added
@patch('workbench_agent.handlers._fetch_display_save_results') # Corrected function name
def test_handle_import_da_success(mock_fetch, mock_print_summary, mock_wait, mock_start_da, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests the successful execution of handle_import_da."""
    mock_params.command = 'import-da'; mock_params.project_name = "DAProj"; mock_params.scan_name = "DAScan"; mock_params.path = "/path/to/results.json"
    mock_resolve_proj.return_value = "DA_PROJ_C"
    mock_resolve_scan.return_value = ("DA_SCAN_C", 890)

    handlers.handle_import_da(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once_with(mock_workbench, "DAProj", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name="DAScan", project_name="DAProj", create_if_missing=True, params=mock_params)
    mock_upload.assert_called_once_with("DA_SCAN_C", "/path/to/results.json", is_da_import=True)
    mock_start_da.assert_called_once_with("DA_SCAN_C", import_only=True) # Check DA start call
    mock_wait.assert_called_once_with("DEPENDENCY_ANALYSIS", "DA_SCAN_C", mock_params.scan_number_of_tries, mock_params.scan_wait_time) # Check wait args
    mock_print_summary.assert_called_once_with(mock_params, True, "DA_PROJ_C", "DA_SCAN_C", {"dependency_analysis": 0.0}) # Check summary call
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "DA_SCAN_C") # Check fetch call (only needs scan_code)

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.start_dependency_analysis', side_effect=ApiError("Failed to start DA")) # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers._print_operation_summary') # Added
@patch('workbench_agent.handlers._fetch_display_save_results') # Corrected
def test_handle_import_da_start_da_fails(mock_fetch, mock_print_summary, mock_wait, mock_start_da, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure during start_dependency_analysis."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(ApiError, match="Failed to start DA"):
        handlers.handle_import_da(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_start_da.assert_called_once() # Start DA is called and fails
    mock_wait.assert_not_called() # Wait should not be called
    mock_print_summary.assert_not_called() # Summary should not be called
    mock_fetch.assert_not_called() # Fetch should not be called

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files', side_effect=FileSystemError("Cannot read results file"))
@patch('workbench_agent.handlers.Workbench.start_dependency_analysis')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers._fetch_display_save_results') # Corrected
def test_handle_import_da_upload_fails_filesystem(mock_fetch, mock_wait, mock_start_da, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure during upload_files (FileSystemError)."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    with pytest.raises(FileSystemError, match="Cannot read results file"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_start_da.assert_not_called() # Should fail before starting DA
    mock_wait.assert_not_called()
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files', side_effect=NetworkError("Upload connection failed"))
@patch('workbench_agent.handlers.Workbench.start_dependency_analysis')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers._fetch_display_save_results') # Corrected
def test_handle_import_da_upload_fails_network(mock_fetch, mock_wait, mock_start_da, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure during upload_files (NetworkError)."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    with pytest.raises(NetworkError, match="Upload connection failed"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_start_da.assert_not_called()
    mock_wait.assert_not_called()
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("DA project not found"))
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
def test_handle_import_da_project_not_found(mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of ProjectNotFoundError from _resolve_project."""
    mock_params.command = 'import-da'; mock_params.project_name = "NonExistent"; mock_params.scan_name = "S"; mock_params.path = "p"
    with pytest.raises(ProjectNotFoundError, match="DA project not found"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()
    mock_upload.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("DA scan not found"))
@patch('workbench_agent.handlers.Workbench.upload_files')
def test_handle_import_da_scan_not_found(mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of ScanNotFoundError from _resolve_scan."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "NonExistent"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    with pytest.raises(ScanNotFoundError, match="DA scan not found"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=CompatibilityError("Scan exists but is not DA"))
@patch('workbench_agent.handlers.Workbench.upload_files')
def test_handle_import_da_compatibility_error(mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of CompatibilityError from _resolve_scan."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "ExistingNonDA"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    with pytest.raises(CompatibilityError, match="Scan exists but is not DA"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.start_dependency_analysis')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish', side_effect=ProcessError("Scan failed during processing"))
@patch('workbench_agent.handlers._fetch_display_save_results') # Corrected
def test_handle_import_da_wait_process_error(mock_fetch, mock_wait, mock_start_da, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of ProcessError from wait_for_scan_to_finish."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    with pytest.raises(ProcessError, match="Scan failed during processing"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_start_da.assert_called_once()
    mock_wait.assert_called_once()
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.start_dependency_analysis')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish', side_effect=ProcessTimeoutError("Scan timed out"))
@patch('workbench_agent.handlers._fetch_display_save_results') # Corrected
def test_handle_import_da_wait_timeout_error(mock_fetch, mock_wait, mock_start_da, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of ProcessTimeoutError from wait_for_scan_to_finish."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    with pytest.raises(ProcessTimeoutError, match="Scan timed out"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_start_da.assert_called_once()
    mock_wait.assert_called_once()
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.start_dependency_analysis')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers._print_operation_summary') # Added
@patch('workbench_agent.handlers._fetch_display_save_results', side_effect=ApiError("Error fetching results")) # Corrected
def test_handle_import_da_fetch_api_error(mock_fetch, mock_print_summary, mock_wait, mock_start_da, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of ApiError from _fetch_display_save_results."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    with pytest.raises(ApiError, match="Error fetching results"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_start_da.assert_called_once()
    mock_wait.assert_called_once()
    mock_print_summary.assert_called_once() # Summary is called before fetch
    mock_fetch.assert_called_once() # Error happens during fetch

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.start_dependency_analysis')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers._print_operation_summary') # Added
@patch('workbench_agent.handlers._fetch_display_save_results', side_effect=Exception("Unexpected fetch failure")) # Corrected
def test_handle_import_da_unexpected_error(mock_fetch, mock_print_summary, mock_wait, mock_start_da, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that unexpected errors are wrapped in WorkbenchAgentError."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    with pytest.raises(WorkbenchAgentError, match="Unexpected fetch failure"):
        handlers.handle_import_da(mock_workbench, mock_params)
    mock_start_da.assert_called_once()
    mock_wait.assert_called_once()
    mock_print_summary.assert_called_once()
    mock_fetch.assert_called_once()
