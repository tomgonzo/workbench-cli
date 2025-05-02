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
    mock_params.show_licenses = True  # Need at least one show flag
    
    # Mock the resolution functions
    monkeypatch.setattr(handlers.show_results, '_resolve_project', lambda wb, pn, **kwargs: "PROJ_A_CODE")
    monkeypatch.setattr(handlers.show_results, '_resolve_scan', lambda wb, **kwargs: ("SCAN_1_CODE", 123))
    
    # Mock wait_for_scan_completion
    mock_wait_completion = MagicMock(return_value=(True, True, {"kb_scan": 30.0, "dependency_analysis": 20.0}))
    monkeypatch.setattr(handlers.show_results, '_wait_for_scan_completion', mock_wait_completion)
    
    # Mock fetch_display_save_results
    mock_fetch = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_fetch_display_save_results', mock_fetch)
    
    # Call handler
    handlers.handle_show_results(mock_workbench, mock_params)
    
    # Verify mocks were called correctly
    mock_wait_completion.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")
    mock_fetch.assert_called_once_with(mock_workbench, mock_params, "SCAN_1_CODE")

def test_handle_show_results_scan_incomplete(monkeypatch, mock_workbench, mock_params):
    """Tests show-results when scan is incomplete."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True  # Need at least one show flag
    
    # Mock the resolution functions
    monkeypatch.setattr(handlers.show_results, '_resolve_project', lambda wb, pn, **kwargs: "PROJ_A_CODE")
    monkeypatch.setattr(handlers.show_results, '_resolve_scan', lambda wb, **kwargs: ("SCAN_1_CODE", 123))
    
    # Mock wait_for_scan_completion - scan not completed
    mock_wait_completion = MagicMock(return_value=(False, False, {"kb_scan": 0.0, "dependency_analysis": 0.0}))
    monkeypatch.setattr(handlers.show_results, '_wait_for_scan_completion', mock_wait_completion)
    
    # Mock fetch_display_save_results
    mock_fetch = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_fetch_display_save_results', mock_fetch)
    
    # Call handler - should raise error
    with pytest.raises(ProcessError, match="Cannot show results because the scan has not completed successfully"):
        handlers.handle_show_results(mock_workbench, mock_params)
    
    # Verify what mocks were called
    mock_wait_completion.assert_called_once()
    mock_fetch.assert_not_called()

def test_handle_show_results_project_resolve_fails(monkeypatch, mock_workbench, mock_params):
    """Tests show-results when project resolve fails."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA" 
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True
    
    # Mock the resolution function to fail
    def mock_resolve_project_fails(*args, **kwargs):
        raise ProjectNotFoundError("Proj Not Found")
    
    monkeypatch.setattr(handlers.show_results, '_resolve_project', mock_resolve_project_fails)
    
    # Mock other functions
    mock_resolve_scan = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_resolve_scan', mock_resolve_scan)
    
    mock_wait_completion = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_wait_for_scan_completion', mock_wait_completion)
    
    mock_fetch = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_fetch_display_save_results', mock_fetch)
    
    # Call handler - should raise error
    with pytest.raises(ProjectNotFoundError, match="Proj Not Found"):
        handlers.handle_show_results(mock_workbench, mock_params)
    
    # Verify what mocks were called
    mock_resolve_scan.assert_not_called()
    mock_wait_completion.assert_not_called()
    mock_fetch.assert_not_called()

def test_handle_show_results_scan_resolve_fails(monkeypatch, mock_workbench, mock_params):
    """Tests show-results when scan resolve fails."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True
    
    # Mock _resolve_project to succeed
    monkeypatch.setattr(handlers.show_results, '_resolve_project', lambda wb, pn, **kwargs: "PROJ_A_CODE")
    
    # Mock the scan resolution function to fail
    def mock_resolve_scan_fails(*args, **kwargs):
        raise ScanNotFoundError("Scan Not Found")
    
    monkeypatch.setattr(handlers.show_results, '_resolve_scan', mock_resolve_scan_fails)
    
    # Mock other functions
    mock_wait_completion = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_wait_for_scan_completion', mock_wait_completion)
    
    mock_fetch = MagicMock()
    monkeypatch.setattr(handlers.show_results, '_fetch_display_save_results', mock_fetch)
    
    # Call handler - should raise error
    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_show_results(mock_workbench, mock_params)
    
    # Verify what mocks were called
    mock_wait_completion.assert_not_called()
    mock_fetch.assert_not_called()

# Note: Errors within _fetch_display_save_results are typically logged, not raised by the handler.
