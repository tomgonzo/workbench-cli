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

def test_handle_show_results_success(monkeypatch, mock_workbench, mock_params):
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
    monkeypatch.setattr(handlers.show_results, '_resolve_project', lambda wb, pn, **kwargs: "PROJ_A_CODE")
    monkeypatch.setattr(handlers.show_results, '_resolve_scan', lambda wb, **kwargs: ("SCAN_1_CODE", 123))
    
    # Mock fetch_display_save_results
    mock_fetch_results = MagicMock(return_value=True)
    monkeypatch.setattr(handlers.show_results, '_fetch_display_save_results', mock_fetch_results)
    
    # Execute
    result = handlers.show_results.handle_show_results(mock_workbench, mock_params)
    
    # Verify
    assert result is True
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")

def test_handle_show_results_scan_incomplete(monkeypatch, mock_workbench, mock_params):
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
    monkeypatch.setattr(handlers.show_results, '_resolve_project', lambda wb, pn, **kwargs: "PROJ_A_CODE")
    monkeypatch.setattr(handlers.show_results, '_resolve_scan', lambda wb, **kwargs: ("SCAN_1_CODE", 123))
    
    # Mock fetch_display_save_results - no fetch results failure
    mock_fetch_results = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_fetch_display_save_results', mock_fetch_results)
    
    # Execute
    result = handlers.show_results.handle_show_results(mock_workbench, mock_params)
    
    # Verify
    assert result is True
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")

def test_handle_show_results_project_resolve_fails(monkeypatch, mock_workbench, mock_params):
    """Tests show-results when project resolve fails."""
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
    
    # Mock the resolution function to fail
    def mock_resolve_project_fails(*args, **kwargs):
        raise ProjectNotFoundError("Proj Not Found")
    
    monkeypatch.setattr(handlers.show_results, '_resolve_project', mock_resolve_project_fails)
    
    # Mock other functions
    mock_resolve_scan = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_resolve_scan', mock_resolve_scan)
    
    mock_fetch_results = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_fetch_display_save_results', mock_fetch_results)
    
    # Execute and verify
    with pytest.raises(ProjectNotFoundError, match="Proj Not Found"):
        handlers.show_results.handle_show_results(mock_workbench, mock_params)
    
    # Neither of these should be called
    mock_resolve_scan.assert_not_called()
    mock_fetch_results.assert_not_called()

def test_handle_show_results_scan_resolve_fails(monkeypatch, mock_workbench, mock_params):
    """Tests show-results when scan resolve fails."""
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
    
    # Mock _resolve_project to succeed
    monkeypatch.setattr(handlers.show_results, '_resolve_project', lambda wb, pn, **kwargs: "PROJ_A_CODE")
    
    # Mock the scan resolution function to fail
    def mock_resolve_scan_fails(*args, **kwargs):
        raise ScanNotFoundError("Scan Not Found")
    
    monkeypatch.setattr(handlers.show_results, '_resolve_scan', mock_resolve_scan_fails)
    
    # Mock other functions
    mock_fetch_results = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_fetch_display_save_results', mock_fetch_results)
    
    # Execute and verify
    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.show_results.handle_show_results(mock_workbench, mock_params)
    
    # This should not be called
    mock_fetch_results.assert_not_called()

# Note: Errors within _fetch_display_save_results are typically logged, not raised by the handler.
