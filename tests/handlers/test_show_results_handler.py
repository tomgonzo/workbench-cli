# tests/handlers/test_show_results_handler.py

import pytest
from unittest.mock import MagicMock, patch, call
import json
import unittest

# Import handler and dependencies
from workbench_cli import handlers
from workbench_cli.exceptions import (
    ProjectNotFoundError,
    ScanNotFoundError,
    ProcessError,
    ApiError,
    NetworkError,
    ValidationError,
    ProcessTimeoutError
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

# Use a consistent mock for the WorkbenchAPI instance
@patch('workbench_cli.main.WorkbenchAPI')
class TestShowResultsHandler(unittest.TestCase):

    @patch('workbench_cli.utilities.scan_workflows.fetch_display_save_results', return_value=True)
    @patch('workbench_cli.utilities.scan_workflows.wait_for_scan_completion', return_value=(True, True, {}))
    def test_handle_show_results_success(self, mock_wait, mock_fetch, MockWorkbenchAPI):
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
        self.assertTrue(result)
        mock_wait.assert_called_once()
        mock_fetch.assert_called_once()

    @patch('workbench_cli.utilities.scan_workflows.fetch_display_save_results')
    @patch('workbench_cli.utilities.scan_workflows.wait_for_scan_completion', return_value=(False, False, {}))
    def test_handle_show_results_scan_not_completed(self, mock_wait, mock_fetch, MockWorkbenchAPI):
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
        self.assertTrue(result)
        mock_wait.assert_called_once()
        mock_fetch.assert_called_once()

    @patch('workbench_cli.utilities.scan_workflows.wait_for_scan_completion', side_effect=ProcessTimeoutError("Timed out"))
    def test_handle_show_results_wait_timeout(self, mock_wait, MockWorkbenchAPI):
        """Tests show-results when wait timeout occurs."""
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
        
        # Execute and verify
        with self.assertRaises(ProcessTimeoutError):
            handlers.show_results.handle_show_results(mock_workbench, mock_params)
        mock_wait.assert_called_once()

    def test_validation_error_no_show_flags(self, MockWorkbenchAPI):
        """Tests show-results when no show flags are provided."""
        # Setup mocks
        mock_params.command = 'show-results'
        mock_params.project_name = "ProjA"
        mock_params.scan_name = "Scan1"
        mock_params.show_licenses = False
        mock_params.show_components = False
        mock_params.show_dependencies = False
        mock_params.show_scan_metrics = False
        mock_params.show_policy_warnings = False
        mock_params.show_vulnerabilities = False
        
        # Execute and verify
        with self.assertRaises(ValidationError):
            handlers.show_results.handle_show_results(mock_workbench, mock_params)

    # Note: Errors within fetch_display_save_results are typically logged, not raised by the handler.
    # We can test that the handler continues execution.
    @patch('workbench_cli.utilities.scan_workflows.fetch_display_save_results', side_effect=ApiError("API Error"))
    @patch('workbench_cli.utilities.scan_workflows.wait_for_scan_completion', return_value=(True, True, {}))
    def test_handle_show_results_fetch_api_error(self, mock_wait, mock_fetch, MockWorkbenchAPI):
        """Tests show-results when fetch API error occurs."""
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
        
        # Execute and verify
        with self.assertRaises(ApiError):
            handlers.show_results.handle_show_results(mock_workbench, mock_params)
        mock_wait.assert_called_once()
        mock_fetch.assert_called_once()

@patch('workbench_cli.utilities.scan_workflows.fetch_display_save_results', return_value=True)
@patch('workbench_cli.utilities.scan_workflows.wait_for_scan_completion', return_value=(True, True, {}))
def test_handle_show_results_success(mock_wait, mock_fetch, mock_workbench, mock_params):
    """Tests show-results success case."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    
    # Execute
    result = handlers.show_results.handle_show_results(mock_workbench, mock_params)
    
    # Verify
    assert result is True
    mock_wait.assert_called_once()
    mock_fetch.assert_called_once()

@patch('workbench_cli.utilities.scan_workflows.fetch_display_save_results')
@patch('workbench_cli.utilities.scan_workflows.wait_for_scan_completion', return_value=(False, False, {}))
def test_handle_show_results_scan_incomplete(mock_wait, mock_fetch, mock_workbench, mock_params):
    """Tests show-results when scan is incomplete."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    
    # Execute
    result = handlers.show_results.handle_show_results(mock_workbench, mock_params)
    
    # Verify
    assert result is True
    mock_wait.assert_called_once()
    mock_fetch.assert_called_once()

def test_handle_show_results_project_resolve_fails(mock_workbench, mock_params):
    """Tests show-results when project resolution fails."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "NonExistent"
    mock_workbench.helpers.projects.get_project_code_from_name.side_effect = ProjectNotFoundError("Project not found")
    
    # Execute and verify
    with pytest.raises(ProjectNotFoundError):
        handlers.show_results.handle_show_results(mock_workbench, mock_params)

def test_handle_show_results_scan_resolve_fails(mock_workbench, mock_params):
    """Tests show-results when scan resolution fails."""
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "NonExistent"
    mock_workbench.helpers.scans.get_scan_code_from_name.side_effect = ScanNotFoundError("Scan not found")
    
    # Execute and verify
    with pytest.raises(ScanNotFoundError):
        handlers.show_results.handle_show_results(mock_workbench, mock_params)
