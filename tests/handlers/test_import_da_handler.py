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
from ..exceptions import ApiError, FileSystemError, ProjectNotFoundError, ScanNotFoundError, ValidationError
from .. import handlers

@patch('workbench_cli.handlers.import_da.fetch_display_save_results')
@patch('workbench_cli.handlers.import_da.wait_for_scan_completion', return_value=(True, True, {}))
@patch('workbench_cli.handlers.import_da.assert_scan_is_idle')
def test_handle_import_da_success(mock_assert_idle, mock_wait, mock_fetch, mock_workbench, mock_params):
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
    mock_workbench.resolve_project.assert_called_once()
    mock_workbench.resolve_scan.assert_called_once()
    mock_workbench.upload_files.assert_called_once()
    mock_workbench.scans.start_dependency_analysis.assert_called_once_with(scan_code="SCAN_1_CODE", dependency_file_path="/fake/path")
    mock_wait.assert_called_once()
    mock_fetch.assert_called_once()

@patch('workbench_cli.handlers.import_da.fetch_display_save_results')
@patch('workbench_cli.handlers.import_da.wait_for_scan_completion', return_value=(True, True, {}))
@patch('workbench_cli.handlers.import_da.assert_scan_is_idle')
def test_handle_import_da_no_wait(mock_assert_idle, mock_wait, mock_fetch, mock_workbench, mock_params):
    """Tests the execution of handle_import_da with no wait."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "DAProj"
    mock_params.scan_name = "DAScan"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    mock_params.no_wait = True
    
    # Configure mocks
    mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
    mock_workbench.resolve_scan.return_value = ('TEST_SCAN_CODE', 123)
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 5.0)

    # Execute the handler
    result = import_da.handle_import_da(mock_workbench, mock_params)
    
    # Verify the result and expected calls
    assert result is True
    mock_workbench.resolve_project.assert_called_once()
    mock_workbench.resolve_scan.assert_called_once()
    mock_workbench.upload_files.assert_called_once()
    mock_workbench.scans.start_dependency_analysis.assert_called_once()
    mock_wait.assert_not_called()
    mock_fetch.assert_not_called()

def test_handle_import_da_scan_not_found(mock_workbench, mock_params):
    """Tests the execution of handle_import_da with a scan not found."""
    # Configure params
    mock_params.command = 'import-da'
    mock_params.project_name = "DAProj"
    mock_params.scan_name = "DAScan"
    mock_params.path = "/path/to/results.json"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    
    # Configure mocks
    mock_workbench.resolve_project.return_value = 'TEST_PROJ_CODE'
    mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")

    # Execute and verify exception
    with pytest.raises(ScanNotFoundError):
        handlers.import_da.handle_import_da(mock_workbench, mock_params)

@patch('workbench_cli.handlers.import_da.fetch_display_save_results', side_effect=ApiError("Error fetching results"))
@patch('workbench_cli.handlers.import_da.wait_for_scan_completion', return_value=(True, True, {}))
@patch('workbench_cli.handlers.import_da.assert_scan_is_idle')
def test_handle_import_da_fetch_api_error(mock_assert_idle, mock_wait, mock_fetch, mock_workbench, mock_params):
    """Tests propagation of ApiError from fetch_display_save_results."""
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
    with pytest.raises(ApiError):
        handlers.import_da.handle_import_da(mock_workbench, mock_params)
    mock_fetch.assert_called_once()

@patch('workbench_cli.handlers.import_da.fetch_display_save_results', side_effect=Exception("Unexpected fetch failure"))
@patch('workbench_cli.handlers.import_da.wait_for_scan_completion', return_value=(True, True, {}))
@patch('workbench_cli.handlers.import_da.assert_scan_is_idle')
def test_handle_import_da_fetch_unexpected_error(mock_assert_idle, mock_wait, mock_fetch, mock_workbench, mock_params):
    """Tests propagation of generic Exception from fetch_display_save_results."""
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
    with pytest.raises(Exception):
        handlers.import_da.handle_import_da(mock_workbench, mock_params)
    mock_fetch.assert_called_once()
