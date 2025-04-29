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
    CompatibilityError # Import needed
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish') # Patch the wait function
@patch('workbench_agent.handlers.fetch_and_process_results') # Patch result fetching
def test_handle_import_da_success(mock_fetch, mock_wait, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests the successful execution of handle_import_da."""
    # Setup mock_params for import-da
    mock_params.command = 'import-da'
    mock_params.project_name = "DAProj"
    mock_params.scan_name = "DAScan"
    mock_params.path = "/path/to/results.json"
    mock_resolve_proj.return_value = "DA_PROJ_C"
    mock_resolve_scan.return_value = ("DA_SCAN_C", 890) # scan_code, scan_id

    # Call the handler
    handlers.handle_import_da(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once_with(mock_workbench, "DAProj", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench,
        scan_name="DAScan",
        project_name="DAProj",
        create_if_missing=True,
        params=mock_params # Pass params for DA compatibility check and creation
    )
    mock_upload.assert_called_once_with("DA_SCAN_C", "/path/to/results.json", is_da_import=True)
    # Assert wait_for_scan_to_finish was called correctly
    mock_wait.assert_called_once_with(
        "SCAN", "DA_SCAN_C", mock_params.scan_number_of_tries, mock_params.scan_wait_time
    )
    # Assert fetch_and_process_results was called
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "DA_PROJ_C", "DA_SCAN_C", 890)

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files', side_effect=FileSystemError("Cannot read results file"))
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_import_da_upload_fails_filesystem(mock_fetch, mock_wait, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure during upload_files (FileSystemError)."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(FileSystemError, match="Cannot read results file"):
        handlers.handle_import_da(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_wait.assert_not_called() # Should fail before waiting
    mock_fetch.assert_not_called() # Should fail before fetching

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files', side_effect=NetworkError("Upload connection failed"))
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_import_da_upload_fails_network(mock_fetch, mock_wait, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure during upload_files (NetworkError)."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(NetworkError, match="Upload connection failed"):
        handlers.handle_import_da(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
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
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish', side_effect=ProcessError("Scan failed during processing"))
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_import_da_wait_process_error(mock_fetch, mock_wait, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of ProcessError from wait_for_scan_to_finish."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(ProcessError, match="Scan failed during processing"):
        handlers.handle_import_da(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_wait.assert_called_once()
    mock_fetch.assert_not_called() # Should fail before fetching

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish', side_effect=ProcessTimeoutError("Scan timed out"))
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_import_da_wait_timeout_error(mock_fetch, mock_wait, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of ProcessTimeoutError from wait_for_scan_to_finish."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(ProcessTimeoutError, match="Scan timed out"):
        handlers.handle_import_da(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_wait.assert_called_once()
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.fetch_and_process_results', side_effect=ApiError("Error fetching results"))
def test_handle_import_da_fetch_api_error(mock_fetch, mock_wait, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests propagation of ApiError from fetch_and_process_results."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(ApiError, match="Error fetching results"):
        handlers.handle_import_da(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_wait.assert_called_once()
    mock_fetch.assert_called_once() # Error happens during fetch

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.fetch_and_process_results', side_effect=Exception("Unexpected fetch failure"))
def test_handle_import_da_unexpected_error(mock_fetch, mock_wait, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that unexpected errors are wrapped in WorkbenchAgentError."""
    mock_params.command = 'import-da'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "p"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(WorkbenchAgentError, match="Unexpected fetch failure"):
        handlers.handle_import_da(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once()
    mock_wait.assert_called_once()
    mock_fetch.assert_called_once()
