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

def test_handle_download_reports_scan_sync(monkeypatch, mock_workbench, mock_params, tmpdir):
    """Tests downloading a synchronous report for a scan."""
    # Set up parameters
    mock_params.command = 'download-reports'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'
    mock_params.report_type = 'html'
    mock_params.report_save_path = str(tmpdir)  # Use tmpdir fixture instead of "/out"
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
    
    # Mock wait_for_scan_completion
    mock_wait_completion = MagicMock(return_value=(True, True, {"kb_scan": 45.0, "dependency_analysis": 30.0}))
    monkeypatch.setattr(handlers.download_reports, '_wait_for_scan_completion', mock_wait_completion)
    
    mock_print_summary = MagicMock()
    monkeypatch.setattr('workbench_agent.utils._print_operation_summary', mock_print_summary)
    
    # Mock response from generate_report
    mock_response = MagicMock(spec=requests.Response)
    mock_response.headers = {'content-type': 'text/html'}
    mock_response.content = b"<html>Test report content</html>"
    monkeypatch.setattr(mock_workbench, 'generate_report', lambda **kwargs: mock_response)
    
    # Run the function
    handlers.handle_download_reports(mock_workbench, mock_params)
    
    # Verify that the report was saved
    expected_report_path = tmpdir.join("scan-S-html.html")
    assert expected_report_path.exists()
    assert expected_report_path.read() == "<html>Test report content</html>"
    
    # Verify calls
    mock_wait_completion.assert_called_once_with(mock_workbench, mock_params, "SC")

def test_handle_download_reports_scan_incomplete(monkeypatch, mock_workbench, mock_params):
    """Tests handling of incomplete scan."""
    # Set up parameters
    mock_params.command = 'download-reports'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'
    mock_params.report_type = 'html'
    mock_params.report_save_path = "/out"
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
    
    # Mock _wait_for_scan_completion to return scan completion as False
    monkeypatch.setattr(handlers.download_reports, '_wait_for_scan_completion', 
                        lambda *args, **kwargs: (False, False, {"kb_scan": 0.0, "dependency_analysis": 0.0}))

    # In the actual implementation, ProcessError is raised but then caught and re-raised as WorkbenchAgentError
    with pytest.raises(WorkbenchAgentError, match="Error resolving project/scan: Cannot generate reports because the scan has not completed successfully"):
        handlers.handle_download_reports(mock_workbench, mock_params)

@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils._resolve_scan')
@patch('os.makedirs')
@patch('workbench_agent.api.Workbench.generate_report')
@patch('workbench_agent.api.Workbench._wait_for_process') # Mock the generic waiter
@patch('workbench_agent.api.Workbench.download_report')
@patch('workbench_agent.utils._save_report_content')
def test_handle_download_reports_project_async_old(mock_save, mock_download, mock_wait, mock_gen_report, mock_makedirs, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = None
    mock_params.report_scope = 'project'; mock_params.report_type = 'xlsx'; mock_params.report_save_path = "/out"
    mock_params.selection_type=None; mock_params.selection_view=None; mock_params.disclaimer=None; mock_params.include_vex=True
    mock_resolve_proj.return_value = "PC"
    mock_gen_report.return_value = 12345 # Simulate async process ID
    mock_download_response = MagicMock(spec=requests.Response)
    mock_download_response.headers = {'content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
    mock_download.return_value = mock_download_response

    handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once_with(mock_workbench, "P", create_if_missing=False)
    mock_resolve_scan.assert_not_called()
    mock_makedirs.assert_called_once_with("/out", exist_ok=True)
    mock_gen_report.assert_called_once_with(scope='project', project_code='PC', scan_code=None, report_type='xlsx', selection_type=None, selection_view=None, disclaimer=None, include_vex=True)
    # Check that waiting happened correctly
    mock_wait.assert_called_once()
    wait_args, wait_kwargs = mock_wait.call_args
    assert wait_kwargs['process_description'] == "'xlsx' report generation (Process ID: 12345)" # Check description
    assert wait_kwargs['check_function'] == mock_workbench.check_report_generation_status # Check correct function passed
    assert wait_kwargs['check_args']['process_id'] == 12345 # Check process ID passed in check_args
    assert wait_kwargs['check_args']['scope'] == 'project'
    assert wait_kwargs['check_args']['project_code'] == 'PC'

    mock_download.assert_called_once_with('project', 12345)
    mock_save.assert_called_once_with(mock_download_response, "/out", report_scope='project', name_component='P', report_type='xlsx')

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

# --- test global scan resolution ---
@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils._resolve_scan')
@patch('workbench_agent.api.Workbench.list_scans')
@patch('os.makedirs')
@patch('workbench_agent.utils._wait_for_scan_completion')
@patch('workbench_agent.utils._print_operation_summary')
@patch('workbench_agent.api.Workbench.generate_report')
@patch('workbench_agent.utils._save_report_content')
def test_handle_download_reports_scan_global_resolve(monkeypatch, mock_save, mock_gen_report, mock_print_summary, mock_wait_completion, mock_makedirs, mock_list_scans, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params, tmpdir):
    """Tests downloading report for a scan resolved globally (no project name provided)."""
    # Set up parameters
    mock_params.command = 'download-reports'
    mock_params.project_name = None  # No project name
    mock_params.scan_name = "GlobalScan"
    mock_params.report_scope = 'scan'
    mock_params.report_type = 'json'
    mock_params.report_save_path = str(tmpdir)
    mock_params.selection_type = None
    mock_params.selection_view = None
    mock_params.disclaimer = None
    mock_params.include_vex = True
    
    # Set up Workbench.SCAN_REPORT_TYPES mock data
    mock_scan_report_types = {'html', 'xlsx', 'json', 'cyclone_dx', 'spdx', 'spdx_lite', 'string_match'}
    monkeypatch.setattr(Workbench, 'SCAN_REPORT_TYPES', mock_scan_report_types)
    
    # Mock _resolve_scan to return a global scan
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda *args, **kwargs: ("GLOBAL_SC", 999))
    
    # Mock list_scans to provide project context for the globally resolved scan
    scans_list = [
        {"name": "OtherScan", "code": "OSC", "id": "111", "project_code": "OTHER_PC"},
        {"name": "GlobalScan", "code": "GLOBAL_SC", "id": "999", "project_code": "FOUND_PC"}  # Found scan with project
    ]
    monkeypatch.setattr(mock_workbench, 'list_scans', lambda: scans_list)
    
    # Mock _wait_for_scan_completion to return scan completion as True
    monkeypatch.setattr(handlers.download_reports, '_wait_for_scan_completion', 
                        lambda *args, **kwargs: (True, True, {"kb_scan": 60.0, "dependency_analysis": 40.0}))
    
    # Mock generate_report
    mock_response = MagicMock(spec=requests.Response)
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.content = b'{"test": "JSON content"}'
    monkeypatch.setattr(mock_workbench, 'generate_report', lambda **kwargs: mock_response)
    
    # Run the function
    handlers.handle_download_reports(mock_workbench, mock_params)
    
    # Verify that the report was saved
    expected_report_path = tmpdir.join("scan-GlobalScan-json.json")
    assert expected_report_path.exists()
    assert expected_report_path.read() == '{"test": "JSON content"}'

@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils._resolve_scan')
@patch('workbench_agent.api.Workbench.list_scans', return_value=[]) # Mock list_scans used for project lookup
def test_handle_download_reports_scan_global_resolve_project_fail(mock_list_scans_lookup, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure when project context cannot be found for a globally resolved scan."""
    mock_params.command = 'download-reports'; mock_params.project_name = None; mock_params.scan_name = "GlobalScan"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'json'
    mock_resolve_scan.return_value = ("GLOBAL_SC", 999) # Scan resolves globally

    with pytest.raises(ProjectNotFoundError, match="Could not determine project context for globally found scan 'GLOBAL_SC'"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_scan.assert_called_once()
    mock_list_scans_lookup.assert_called_once()

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

def test_handle_download_reports_scan_global_resolve_new(monkeypatch, mock_workbench, mock_params, tmpdir):
    """Tests downloading report for a scan resolved globally (no project name provided)."""
    # Set up parameters
    mock_params.command = 'download-reports'
    mock_params.project_name = None  # No project name
    mock_params.scan_name = "GlobalScan"
    mock_params.report_scope = 'scan'
    mock_params.report_type = 'json'
    mock_params.report_save_path = str(tmpdir)
    mock_params.selection_type = None
    mock_params.selection_view = None
    mock_params.disclaimer = None
    mock_params.include_vex = True
    
    # Set up Workbench.SCAN_REPORT_TYPES mock data
    mock_scan_report_types = {'html', 'xlsx', 'json', 'cyclone_dx', 'spdx', 'spdx_lite', 'string_match'}
    monkeypatch.setattr(Workbench, 'SCAN_REPORT_TYPES', mock_scan_report_types)
    
    # Mock _resolve_scan to return a global scan
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda *args, **kwargs: ("GLOBAL_SC", 999))
    
    # Mock list_scans to provide project context for the globally resolved scan
    scans_list = [
        {"name": "OtherScan", "code": "OSC", "id": "111", "project_code": "OTHER_PC"},
        {"name": "GlobalScan", "code": "GLOBAL_SC", "id": "999", "project_code": "FOUND_PC"}  # Found scan with project
    ]
    monkeypatch.setattr(mock_workbench, 'list_scans', lambda: scans_list)
    
    # Mock _wait_for_scan_completion to return scan completion as True
    monkeypatch.setattr(handlers.download_reports, '_wait_for_scan_completion', 
                        lambda *args, **kwargs: (True, True, {"kb_scan": 60.0, "dependency_analysis": 40.0}))
    
    # Mock generate_report
    mock_response = MagicMock(spec=requests.Response)
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.content = b'{"test": "JSON content"}'
    monkeypatch.setattr(mock_workbench, 'generate_report', lambda **kwargs: mock_response)
    
    # Run the function
    handlers.handle_download_reports(mock_workbench, mock_params)
    
    # Verify that the report was saved
    expected_report_path = tmpdir.join("scan-GlobalScan-json.txt")
    assert expected_report_path.exists()
    assert expected_report_path.read() == '{"test": "JSON content"}'

def test_handle_download_reports_scan_global_resolve_project_fail_new(monkeypatch, mock_workbench, mock_params):
    """Tests failure when project context cannot be found for a globally resolved scan."""
    # Set up parameters
    mock_params.command = 'download-reports'
    mock_params.project_name = None  # No project name
    mock_params.scan_name = "GlobalScan"
    mock_params.report_scope = 'scan'
    mock_params.report_type = 'json'
    mock_params.report_save_path = "/out"
    
    # Set up Workbench.SCAN_REPORT_TYPES mock data
    mock_scan_report_types = {'html', 'xlsx', 'json', 'cyclone_dx', 'spdx', 'spdx_lite', 'string_match'}
    monkeypatch.setattr(Workbench, 'SCAN_REPORT_TYPES', mock_scan_report_types)
    
    # Mock _resolve_scan to return a global scan
    monkeypatch.setattr(handlers.download_reports, '_resolve_scan', lambda *args, **kwargs: ("GLOBAL_SC", 999))
    
    # Mock list_scans to return an empty list so project context will not be found
    monkeypatch.setattr(mock_workbench, 'list_scans', lambda: [])
    
    # Test that the appropriate error is raised
    with pytest.raises(ProjectNotFoundError, match="Could not determine project context for globally found scan 'GLOBAL_SC'"):
        handlers.handle_download_reports(mock_workbench, mock_params)