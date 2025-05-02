# tests/handlers/test_download_reports_handler.py

import pytest
from unittest.mock import MagicMock, patch, call
import requests # For mocking generate_report response
import os # For mocking os.makedirs

# Import handler and dependencies
from workbench_agent import handlers
from workbench_agent.exceptions import (
    ProcessError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ValidationError, # Added
    WorkbenchAgentError # Added
)
# Import Workbench for type hinting
from workbench_agent.api import Workbench

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

def test_handle_download_reports_scan_sync(monkeypatch, mock_workbench, mock_params):
    """Tests downloading a synchronous report (no async process ID)."""
    # Configure params
    mock_params.command = 'download-reports'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.report_type = "html"
    mock_params.report_scope = "scan"
    mock_params.report_save_path = "reports"
    mock_params.selection_type = None
    mock_params.selection_view = None
    mock_params.disclaimer = None
    mock_params.include_vex = True
    
    # Setup mock responses
    mock_workbench.SCAN_REPORT_TYPES = {'html'}
    mock_workbench.PROJECT_REPORT_TYPES = {'html'}
    mock_workbench.ASYNC_REPORT_TYPES = {'xlsx'}
    
    # Setup _resolve functions to return expected values
    monkeypatch.setattr(handlers.download_reports, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Mock makedirs to avoid file system operations
    monkeypatch.setattr(os, 'makedirs', lambda *args, **kwargs: None)
    monkeypatch.setattr(os.path, 'exists', lambda path: True)
    
    # Mock the generate_report to return a Response object for HTML report
    mock_response = MagicMock(spec=requests.Response)
    mock_response.content = b"<html>Report content</html>"
    mock_response.headers = {"Content-Type": "text/html"}
    monkeypatch.setattr(mock_workbench, 'generate_report', lambda **kwargs: mock_response)
    
    # Mock save_report_content to verify it's called with the response
    mock_save = MagicMock()
    monkeypatch.setattr(handlers.download_reports, '_save_report_content', mock_save)
    
    # Call the handler
    result = handlers.download_reports.handle_download_reports(mock_workbench, mock_params)
    
    # Verify
    mock_save.assert_called_once()
    assert result is True

def test_handle_download_reports_scan_incomplete(monkeypatch, mock_workbench, mock_params):
    """Tests downloading reports when scan is not complete."""
    # Configure params
    mock_params.command = 'download-reports'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.report_type = "html"
    mock_params.report_scope = "scan"
    mock_params.report_save_path = "reports"
    mock_params.selection_type = None
    mock_params.selection_view = None
    mock_params.disclaimer = None
    mock_params.include_vex = True
    
    # Setup mock responses
    mock_workbench.SCAN_REPORT_TYPES = {'html'}
    mock_workbench.PROJECT_REPORT_TYPES = {'html'}
    mock_workbench.ASYNC_REPORT_TYPES = {'xlsx'}
    
    # Setup _resolve functions to return expected values
    monkeypatch.setattr(handlers.download_reports, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Mock makedirs to avoid file system operations
    monkeypatch.setattr(os, 'makedirs', lambda *args, **kwargs: None)
    monkeypatch.setattr(os.path, 'exists', lambda path: True)
    
    # Mock the generate_report to return a Response object for HTML report
    mock_response = MagicMock(spec=requests.Response)
    mock_response.content = b"<html>Report content</html>"
    mock_response.headers = {"Content-Type": "text/html"}
    monkeypatch.setattr(mock_workbench, 'generate_report', lambda **kwargs: mock_response)
    
    # Mock save_report_content to verify it's called with the response
    mock_save = MagicMock()
    monkeypatch.setattr(handlers.download_reports, '_save_report_content', mock_save)
    
    # Call the handler
    result = handlers.download_reports.handle_download_reports(mock_workbench, mock_params)
    
    # Verify
    mock_save.assert_called_once()
    assert result is True

def test_handle_download_reports_project_async(monkeypatch, mock_workbench, mock_params, tmpdir):
    """Tests downloading an asynchronous report for a project."""
    # Set up parameters
    mock_params.command = 'download-reports'
    mock_params.project_name = "P"
    mock_params.scan_name = None
    mock_params.report_scope = 'project'
    mock_params.report_type = 'xlsx'
    mock_params.report_save_path = str(tmpdir)
    mock_params.selection_type = None
    mock_params.selection_view = None
    mock_params.disclaimer = None
    mock_params.include_vex = True
    
    # Set up Workbench.PROJECT_REPORT_TYPES mock data
    mock_project_report_types = {'xlsx', 'cyclone_dx'}
    monkeypatch.setattr(Workbench, 'PROJECT_REPORT_TYPES', mock_project_report_types)
    
    # Mock resolution functions
    monkeypatch.setattr(handlers.download_reports, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    
    # Mock generate_report to return an async process ID
    monkeypatch.setattr(mock_workbench, 'generate_report', lambda **kwargs: 12345)
    
    # Mock wait_for_process
    mock_wait = MagicMock()
    monkeypatch.setattr(mock_workbench, '_wait_for_process', mock_wait)
    
    # Mock download_report
    mock_response = MagicMock(spec=requests.Response)
    mock_response.headers = {'content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
    mock_response.content = b"XLSX test report content"
    monkeypatch.setattr(mock_workbench, 'download_report', lambda *args, **kwargs: mock_response)
    
    # Run the function
    handlers.handle_download_reports(mock_workbench, mock_params)
    
    # Verify that the report was saved
    expected_report_path = tmpdir.join("project-P-xlsx.xlsx")
    assert expected_report_path.exists()
    
    # Verify wait call for the async report
    assert mock_wait.call_count == 1
    wait_args, wait_kwargs = mock_wait.call_args
    assert wait_kwargs['process_description'] == "'xlsx' report generation (Process ID: 12345)"
    assert wait_kwargs['check_function'] == mock_workbench.check_report_generation_status
    assert wait_kwargs['check_args']['process_id'] == 12345
    assert wait_kwargs['check_args']['scope'] == 'project'
    assert wait_kwargs['check_args']['project_code'] == 'PC'

def test_handle_download_reports_multiple_one_fails(monkeypatch, mock_workbench, mock_params, tmpdir):
    """Tests handling of multiple reports where one fails."""
    # Set up parameters
    mock_params.command = 'download-reports'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'
    mock_params.report_type = 'html,xlsx'  # Multiple report types
    mock_params.report_save_path = str(tmpdir)
    mock_params.selection_type = None
    mock_params.selection_view = None
    mock_params.disclaimer = None
    mock_params.include_vex = True
    
    # Set up Workbench.SCAN_REPORT_TYPES mock data
    mock_scan_report_types = {'html', 'xlsx', 'cyclone_dx', 'spdx', 'spdx_lite', 'string_match', 'dynamic_top_matched_components'}
    monkeypatch.setattr(Workbench, 'SCAN_REPORT_TYPES', mock_scan_report_types)
    
    # Mock resolution functions
    monkeypatch.setattr(handlers.download_reports, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda *args, **kwargs: ("SC", 1))
    
    # Mock _wait_for_scan_completion to return scan completion as True
    monkeypatch.setattr(handlers.download_reports, '_wait_for_scan_completion', 
                        lambda *args, **kwargs: (True, True, {"kb_scan": 45.0, "dependency_analysis": 30.0}))
    
    # Mock generate_report to return different responses for HTML (sync) and XLSX (async)
    html_response = MagicMock(spec=requests.Response)
    html_response.headers = {'content-type': 'text/html'}
    html_response.content = b"<html>Test HTML report content</html>"
    
    # Use a side_effect function to return different values based on the report_type argument
    def mock_generate_report(**kwargs):
        if kwargs.get('report_type') == 'html':
            return html_response
        elif kwargs.get('report_type') == 'xlsx':
            return 54321  # Async process ID
        return None
    
    monkeypatch.setattr(mock_workbench, 'generate_report', mock_generate_report)
    
    # Mock _wait_for_process to raise an error for the XLSX report
    def mock_wait_that_fails(*args, **kwargs):
        raise ProcessError("Report generation failed")
    
    monkeypatch.setattr(mock_workbench, '_wait_for_process', mock_wait_that_fails)
    
    # Test that it raises the expected error
    with pytest.raises(ProcessError, match="Failed to process one or more reports: xlsx"):
        handlers.handle_download_reports(mock_workbench, mock_params)
    
    # Verify that the HTML report was saved
    expected_html_path = tmpdir.join("scan-S-html.html")
    assert expected_html_path.exists()
    assert expected_html_path.read() == "<html>Test HTML report content</html>"

def test_handle_download_reports_scan_global_resolve(monkeypatch, mock_workbench, mock_params):
    """Tests downloading reports for scan with global (project-less) resolution."""
    # Configure params
    mock_params.command = 'download-reports'
    mock_params.project_name = None  # No project specified - scan resolved globally
    mock_params.scan_name = "GlobalScan"
    mock_params.report_type = "html"
    mock_params.report_scope = "scan"
    mock_params.report_save_path = "reports"
    mock_params.selection_type = None
    mock_params.selection_view = None
    mock_params.disclaimer = None
    mock_params.include_vex = True
    
    # Setup mock responses
    mock_workbench.SCAN_REPORT_TYPES = {'html'}
    mock_workbench.PROJECT_REPORT_TYPES = {'html'}
    mock_workbench.ASYNC_REPORT_TYPES = {'xlsx'}
    
    # Special mock for global scan resolve - don't need project_code
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda wb, **kwargs: ("GSC", 789))
    
    # Mock makedirs to avoid file system operations
    monkeypatch.setattr(os, 'makedirs', lambda *args, **kwargs: None)
    monkeypatch.setattr(os.path, 'exists', lambda path: True)
    
    # Mock the generate_report to return a Response object for HTML report
    mock_response = MagicMock(spec=requests.Response)
    mock_response.content = b"<html>Global Scan Report</html>"
    mock_response.headers = {"Content-Type": "text/html"}
    monkeypatch.setattr(mock_workbench, 'generate_report', lambda **kwargs: mock_response)
    
    # Mock save_report_content to verify it's called with the response
    mock_save = MagicMock()
    monkeypatch.setattr(handlers.download_reports, '_save_report_content', mock_save)
    
    # Call the handler
    result = handlers.download_reports.handle_download_reports(mock_workbench, mock_params)
    
    # Verify
    mock_save.assert_called_once()
    assert result is True

def test_handle_download_reports_scan_global_resolve_project_fail(monkeypatch, mock_workbench, mock_params):
    """Tests validation error handling for unsupported report types."""
    # Configure params
    mock_params.command = 'download-reports'
    mock_params.project_name = None  # No project specified - scan resolved globally
    mock_params.scan_name = "GlobalScan"
    mock_params.report_type = "unknown"  # Unsupported report type
    mock_params.report_scope = "scan"
    mock_params.report_save_path = "reports"
    mock_params.selection_type = None
    mock_params.selection_view = None
    mock_params.disclaimer = None
    mock_params.include_vex = True
    
    # Setup mock responses
    mock_workbench.SCAN_REPORT_TYPES = {'html'}
    mock_workbench.PROJECT_REPORT_TYPES = {'html'}
    mock_workbench.ASYNC_REPORT_TYPES = {'xlsx'}
    
    # Special mock for global scan resolve - don't need project_code
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda wb, **kwargs: ("GSC", 789))
    
    # Mock makedirs to avoid file system operations
    monkeypatch.setattr(os, 'makedirs', lambda *args, **kwargs: None)
    monkeypatch.setattr(os.path, 'exists', lambda path: True)
    
    # Verify validation error is raised for unknown report type
    with pytest.raises(ValidationError, match="Report type 'unknown' is not supported for scan scope reports"):
        handlers.download_reports.handle_download_reports(mock_workbench, mock_params)

def test_handle_download_reports_invalid_scope(monkeypatch, mock_workbench, mock_params):
    """Tests validation of report scope parameter."""
    mock_params.command = 'download-reports'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.report_scope = 'invalid'  # Invalid scope
    mock_params.report_type = 'html'

    with pytest.raises(ValidationError, match="Invalid report scope: invalid. Must be 'scan' or 'project'."):
        handlers.handle_download_reports(mock_workbench, mock_params)

def test_handle_download_reports_invalid_type(monkeypatch, mock_workbench, mock_params):
    """Tests validation of report type parameter."""
    mock_params.command = 'download-reports'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'
    mock_params.report_type = 'invalid'  # Invalid type
    
    # Set up Workbench.SCAN_REPORT_TYPES mock data
    # This avoids need to mock the actual Workbench class
    mock_scan_report_types = {'html', 'xlsx', 'cyclone_dx', 'spdx', 'spdx_lite', 'string_match', 'dynamic_top_matched_components'}
    monkeypatch.setattr(Workbench, 'SCAN_REPORT_TYPES', mock_scan_report_types)
    
    # Setup monkeypatching for _resolve_project so it returns successfully
    monkeypatch.setattr(handlers.download_reports, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    # Also patch _resolve_scan to prevent it from being called with the real implementation
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda *args, **kwargs: ("SC", 1))
    # Mock _wait_for_scan_completion to return scan completion as True
    monkeypatch.setattr(handlers.download_reports, '_wait_for_scan_completion', 
                        lambda *args, **kwargs: (True, True, {"kb_scan": 45.0, "dependency_analysis": 30.0}))

    with pytest.raises(ValidationError, match="Invalid report type\\(s\\) for 'scan' scope: invalid"):
        handlers.handle_download_reports(mock_workbench, mock_params)

@patch('workbench_agent.handlers.download_reports._resolve_project', side_effect=ProjectNotFoundError("Project 'P' not found and creation was not requested."))
@patch('workbench_agent.utils._resolve_scan')
def test_handle_download_reports_project_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'html'
    with pytest.raises(ProjectNotFoundError, match="Project 'P' not found and creation was not requested."):
        handlers.handle_download_reports(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()

@patch('workbench_agent.handlers.download_reports._resolve_project')
@patch('workbench_agent.handlers.download_reports._resolve_scan', side_effect=ScanNotFoundError("Scan Not Found"))
def test_handle_download_reports_scan_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'html'
    mock_resolve_proj.return_value = "PROJECT_CODE"
    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_download_reports(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()