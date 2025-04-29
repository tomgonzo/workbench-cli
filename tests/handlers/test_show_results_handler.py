# tests/handlers/test_show_results_handler.py

import pytest
from unittest.mock import MagicMock, patch

# Import handler and dependencies
from workbench_agent import handlers
from workbench_agent.exceptions import (
    ProjectNotFoundError,
    ScanNotFoundError
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_show_results_success(mock_fetch, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True # Need at least one show flag
    mock_resolve_proj.return_value = "PROJ_A_CODE"
    mock_resolve_scan.return_value = ("SCAN_1_CODE", 123) # scan_code, scan_id

    # Call handler
    handlers.handle_show_results(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once_with(mock_workbench, "ProjA", create_if_missing=False)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, scan_name="Scan1", project_name="ProjA", create_if_missing=False, params=mock_params
    )
    mock_fetch.assert_called_once_with(
        mock_workbench, mock_params, "PROJ_A_CODE", "SCAN_1_CODE", 123
    )

@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("Proj Not Found"))
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_show_results_project_resolve_fails(mock_fetch, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True

    # Expect the exception from _resolve_project to propagate
    with pytest.raises(ProjectNotFoundError, match="Proj Not Found"):
        handlers.handle_show_results(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called() # Should not be called if project fails
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("Scan Not Found"))
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_show_results_scan_resolve_fails(mock_fetch, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True
    mock_resolve_proj.return_value = "PROJ_A_CODE"

    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_show_results(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_fetch.assert_not_called() # Should not be called if scan fails

# Add tests for ApiError, NetworkError etc. if fetch_and_process_results can raise them directly
# (Currently, errors seem handled within fetch_and_process_results itself, tested in test_utils.py)

