# tests/handlers/test_show_results_handler.py

import pytest
from unittest.mock import MagicMock, patch

# Import handler and dependencies
from workbench_agent import handlers
from workbench_agent.exceptions import (
    ProjectNotFoundError,
    ScanNotFoundError,
    ProcessError
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._wait_for_scan_completion')
@patch('workbench_agent.handlers._print_operation_summary')
@patch('workbench_agent.handlers._fetch_display_save_results')
def test_handle_show_results_success(mock_fetch, mock_print_summary, mock_wait_completion, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks
    mock_params.command = 'show-results'; mock_params.project_name = "ProjA"; mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True # Need at least one show flag
    mock_resolve_proj.return_value = "PROJ_A_CODE"
    mock_resolve_scan.return_value = ("SCAN_1_CODE", 123)
    mock_wait_completion.return_value = (True, True, {"kb_scan": 30.0, "dependency_analysis": 20.0})  # Scan completed, DA completed

    # Call handler
    handlers.handle_show_results(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once_with(mock_workbench, "ProjA", create_if_missing=False)
    mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name="Scan1", project_name="ProjA", create_if_missing=False, params=mock_params)
    mock_wait_completion.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")
    mock_print_summary.assert_called_once_with(mock_params, True, "PROJ_A_CODE", "SCAN_1_CODE", {"kb_scan": 30.0, "dependency_analysis": 20.0})
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._wait_for_scan_completion')
@patch('workbench_agent.handlers._print_operation_summary')
@patch('workbench_agent.handlers._fetch_display_save_results')
def test_handle_show_results_scan_incomplete(mock_fetch, mock_print_summary, mock_wait_completion, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks
    mock_params.command = 'show-results'; mock_params.project_name = "ProjA"; mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True # Need at least one show flag
    mock_resolve_proj.return_value = "PROJ_A_CODE"
    mock_resolve_scan.return_value = ("SCAN_1_CODE", 123)
    mock_wait_completion.return_value = (False, False, {"kb_scan": 0.0, "dependency_analysis": 0.0})  # Scan not completed

    # Call handler
    with pytest.raises(ProcessError, match="Cannot show results because the scan has not completed successfully"):
        handlers.handle_show_results(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_wait_completion.assert_called_once()
    mock_print_summary.assert_not_called()
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("Proj Not Found"))
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._wait_for_scan_completion')
@patch('workbench_agent.handlers._print_operation_summary')
@patch('workbench_agent.handlers._fetch_display_save_results')
def test_handle_show_results_project_resolve_fails(mock_fetch, mock_print_summary, mock_wait_completion, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'show-results'; mock_params.project_name = "ProjA"; mock_params.scan_name = "Scan1"; mock_params.show_licenses = True
    with pytest.raises(ProjectNotFoundError, match="Proj Not Found"):
        handlers.handle_show_results(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()
    mock_wait_completion.assert_not_called()
    mock_print_summary.assert_not_called()
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("Scan Not Found"))
@patch('workbench_agent.handlers._wait_for_scan_completion')
@patch('workbench_agent.handlers._print_operation_summary')
@patch('workbench_agent.handlers._fetch_display_save_results')
def test_handle_show_results_scan_resolve_fails(mock_fetch, mock_print_summary, mock_wait_completion, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'show-results'; mock_params.project_name = "ProjA"; mock_params.scan_name = "Scan1"; mock_params.show_licenses = True
    mock_resolve_proj.return_value = "PROJ_A_CODE"
    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_show_results(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_wait_completion.assert_not_called()
    mock_print_summary.assert_not_called()
    mock_fetch.assert_not_called()

# Note: Errors within _fetch_display_save_results are typically logged, not raised by the handler.
