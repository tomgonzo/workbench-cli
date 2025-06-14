# tests/handlers/test_import_da_handler.py

import pytest
from unittest.mock import MagicMock, patch, call
import os

# Import handler and dependencies
from workbench_cli.handlers import import_da
from workbench_cli.exceptions import (
    ProjectNotFoundError,
    ScanNotFoundError,
    FileSystemError,
    ValidationError,
    ApiError,
    NetworkError,
    WorkbenchCLIError,
    ProcessError,
    ProcessTimeoutError,
    CompatibilityError
)

@patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
@patch('workbench_cli.handlers.import_da._fetch_display_save_results')
@patch('os.path.isfile', return_value=True)
@patch('os.path.exists', return_value=True)
def test_handle_import_da_success(mock_exists, mock_isfile, mock_fetch, mock_ensure_compatibility, mock_workbench, mock_params):
    """Tests the successful execution of handle_import_da."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "DAProj"
    mock_params.scan_name = "DAScan"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Configure mocks
    mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
    mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 5.0)

    # Execute the handler
    result = import_da.handle_import_da(mock_workbench, mock_params)
    
    # Verify the result and expected calls
    assert result is True
    mock_exists.assert_called_once_with(mock_params.path)
    mock_isfile.assert_called_once_with(mock_params.path)
    mock_workbench.resolve_project.assert_called_once()
    mock_workbench.resolve_scan.assert_called_once()
    mock_workbench.upload_files.assert_called_once()
    mock_workbench.start_dependency_analysis.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()
    mock_fetch.assert_called_once()

@patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
@patch('os.path.isfile', return_value=True)
@patch('os.path.exists', return_value=True)
def test_handle_import_da_start_da_fails(mock_exists, mock_isfile, mock_ensure_compatibility, mock_workbench, mock_params):
    """Tests failure during start_dependency_analysis."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Configure mocks
    mock_workbench.resolve_project.return_value = 'PC'
    mock_workbench.resolve_scan.return_value = ('SC', 1)
    mock_workbench.start_dependency_analysis.side_effect = ApiError("Failed to start DA")
    
    # Execute and verify exception
    with pytest.raises(ApiError, match="Failed to start DA"):
        import_da.handle_import_da(mock_workbench, mock_params)

@patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
@patch('os.path.isfile', return_value=True)
@patch('os.path.exists', return_value=True)
def test_handle_import_da_wait_process_error(mock_exists, mock_isfile, mock_ensure_compatibility, mock_workbench, mock_params):
    """Tests propagation of ProcessError from wait_for_scan_to_finish."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Configure mocks
    mock_workbench.resolve_project.return_value = 'PC'
    mock_workbench.resolve_scan.return_value = ('SC', 1)
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessError("Scan failed during processing")

    # Execute and verify exception
    with pytest.raises(ProcessError, match="Scan failed during processing"):
        import_da.handle_import_da(mock_workbench, mock_params)

@patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
@patch('os.path.isfile', return_value=True)
@patch('os.path.exists', return_value=True)
def test_handle_import_da_wait_timeout_error(mock_exists, mock_isfile, mock_ensure_compatibility, mock_workbench, mock_params):
    """Tests propagation of ProcessTimeoutError from wait_for_scan_to_finish."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Configure mocks
    mock_workbench.resolve_project.return_value = 'PC'
    mock_workbench.resolve_scan.return_value = ('SC', 1)
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Scan timed out")

    # Execute and verify exception
    with pytest.raises(ProcessTimeoutError, match="Scan timed out"):
        import_da.handle_import_da(mock_workbench, mock_params)

@patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
@patch('workbench_cli.handlers.import_da._fetch_display_save_results', side_effect=ApiError("Error fetching results"))
@patch('os.path.isfile', return_value=True)
@patch('os.path.exists', return_value=True)
def test_handle_import_da_fetch_api_error(mock_exists, mock_isfile, mock_fetch, mock_ensure_compatibility, mock_workbench, mock_params):
    """Tests propagation of ApiError from _fetch_display_save_results."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5

    # Configure mocks
    mock_workbench.resolve_project.return_value = 'PC'
    mock_workbench.resolve_scan.return_value = ('SC', 1)
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 5.0)

    # Execute and verify exception
    with pytest.raises(ApiError, match="Error fetching results"):
        import_da.handle_import_da(mock_workbench, mock_params)

@patch('workbench_cli.handlers.import_da.ensure_scan_compatibility')
@patch('workbench_cli.handlers.import_da._fetch_display_save_results', side_effect=Exception("Unexpected fetch failure"))
@patch('os.path.isfile', return_value=True)
@patch('os.path.exists', return_value=True)
def test_handle_import_da_unexpected_error(mock_exists, mock_isfile, mock_fetch, mock_ensure_compatibility, mock_workbench, mock_params):
    """Tests that unexpected errors are wrapped in WorkbenchCLIError."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Configure mocks
    mock_workbench.resolve_project.return_value = 'PC'
    mock_workbench.resolve_scan.return_value = ('SC', 1)
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 5.0)

    # Execute and verify exception
    with pytest.raises(WorkbenchCLIError, match="Failed to execute import-da: Unexpected fetch failure"):
        import_da.handle_import_da(mock_workbench, mock_params)
