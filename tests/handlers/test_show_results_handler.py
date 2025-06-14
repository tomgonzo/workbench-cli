# tests/handlers/test_show_results_handler.py

import pytest
from unittest.mock import MagicMock, patch, call
import json

# Import handler and dependencies
from workbench_cli import handlers
from workbench_cli.exceptions import (
    ProjectNotFoundError,
    ScanNotFoundError,
    ProcessError
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_cli.handlers.show_results._fetch_display_save_results', return_value=True)
def test_handle_show_results_success(mock_fetch_results, mock_workbench, mock_params):
    """Tests show-results success case."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True
    mock_params.show_components = False
    mock_params.show_dependencies = False
    mock_params.show_scan_metrics = False
    mock_params.show_policy_warnings = False
    mock_params.show_vulnerabilities = False
    
    # Mock the resolution functions
    mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
    mock_workbench.resolve_scan.return_value = ("SCAN_1_CODE", 123)
    
    # Execute
    result = handlers.show_results.handle_show_results(mock_workbench, mock_params)
    
    # Verify
    assert result is True
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")

@patch('workbench_cli.handlers.show_results._fetch_display_save_results')
def test_handle_show_results_scan_incomplete(mock_fetch_results, mock_workbench, mock_params):
    """Tests show-results when scan is incomplete."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True
    mock_params.show_components = False
    mock_params.show_dependencies = False
    mock_params.show_scan_metrics = False
    mock_params.show_policy_warnings = False
    mock_params.show_vulnerabilities = False
    
    # Mock the resolution functions
    mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
    mock_workbench.resolve_scan.return_value = ("SCAN_1_CODE", 123)
    
    # Execute
    result = handlers.show_results.handle_show_results(mock_workbench, mock_params)
    
    # Verify
    assert result is True
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")

def test_handle_show_results_project_resolve_fails(mock_workbench, mock_params):
    """Tests show-results when project resolve fails."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "non-existent"
    mock_params.show_licenses = False
    mock_params.show_components = False
    mock_params.show_dependencies = False
    mock_params.show_scan_metrics = False
    mock_params.show_policy_warnings = False
    mock_params.show_vulnerabilities = True
    mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")
    
    # Execute and verify
    with pytest.raises(ProjectNotFoundError):
        handlers.show_results.handle_show_results(mock_workbench, mock_params)

def test_handle_show_results_scan_resolve_fails(mock_workbench, mock_params):
    """Tests show-results when scan resolve fails."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "non-existent"
    mock_params.show_licenses = False
    mock_params.show_components = False
    mock_params.show_dependencies = False
    mock_params.show_scan_metrics = False
    mock_params.show_policy_warnings = False
    mock_params.show_vulnerabilities = True
    mock_workbench.resolve_project.return_value = "PROJ_A_CODE"
    mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")
    
    # Execute and verify
    with pytest.raises(ScanNotFoundError):
        handlers.show_results.handle_show_results(mock_workbench, mock_params)

# Note: Errors within _fetch_display_save_results are typically logged, not raised by the handler.
