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
    ValidationError # Added
)
# Import Workbench for type hinting
from workbench_agent.api import Workbench

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('os.makedirs')
@patch('workbench_agent.handlers.Workbench.generate_report')
@patch('workbench_agent.handlers._save_report_content')
def test_handle_download_reports_scan_sync(mock_save, mock_gen_report, mock_makedirs, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'html'; mock_params.report_save_path = "/out"
    mock_params.selection_type=None; mock_params.selection_view=None; mock_params.disclaimer=None; mock_params.include_vex=True # Defaults from handler
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_response = MagicMock(spec=requests.Response)
    mock_response.headers = {'content-type': 'text/html'}
    mock_gen_report.return_value = mock_response

    handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once_with(mock_workbench, "P", create_if_missing=False)
    mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name="S", project_name="P", create_if_missing=False, params=mock_params)
    mock_makedirs.assert_called_once_with("/out", exist_ok=True)
    mock_gen_report.assert_called_once_with(scope='scan', project_code='PC', scan_code='SC', report_type='html', selection_type=None, selection_view=None, disclaimer=None, include_vex=True)
    mock_save.assert_called_once_with(mock_response, "/out", report_scope='scan', name_component='S', report_type='html')

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('os.makedirs')
@patch('workbench_agent.handlers.Workbench.generate_report')
@patch('workbench_agent.handlers.Workbench._wait_for_process') # Mock the generic waiter
@patch('workbench_agent.handlers.Workbench.download_report')
@patch('workbench_agent.handlers._save_report_content')
def test_handle_download_reports_project_async(mock_save, mock_download, mock_wait, mock_gen_report, mock_makedirs, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
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

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('os.makedirs')
@patch('workbench_agent.handlers.Workbench.generate_report')
@patch('workbench_agent.handlers.Workbench._wait_for_process')
@patch('workbench_agent.handlers.Workbench.download_report')
@patch('workbench_agent.handlers._save_report_content')
def test_handle_download_reports_multiple_one_fails(mock_save, mock_download, mock_wait, mock_gen_report, mock_makedirs, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'html,xlsx'; mock_params.report_save_path = "/out"
    mock_params.selection_type=None; mock_params.selection_view=None; mock_params.disclaimer=None; mock_params.include_vex=True
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_sync_response = MagicMock(spec=requests.Response)
    mock_sync_response.headers = {'content-type': 'text/html'}
    mock_wait.side_effect = ProcessError("Report generation failed")
    mock_gen_report.side_effect = [mock_sync_response, 54321]

    with pytest.raises(ProcessError, match="Failed to process one or more reports: xlsx"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_makedirs.assert_called_once()
    assert mock_gen_report.call_count == 2
    mock_gen_report.assert_has_calls([
        call(scope='scan', project_code='PC', scan_code='SC', report_type='html', selection_type=None, selection_view=None, disclaimer=None, include_vex=True),
        call(scope='scan', project_code='PC', scan_code='SC', report_type='xlsx', selection_type=None, selection_view=None, disclaimer=None, include_vex=True)
    ])
    mock_save.assert_called_once_with(mock_sync_response, "/out", report_scope='scan', name_component='S', report_type='html')
    # Check wait call for the async report (xlsx)
    mock_wait.assert_called_once()
    wait_args, wait_kwargs = mock_wait.call_args
    assert wait_kwargs['process_description'] == "'xlsx' report generation (Process ID: 54321)"
    assert wait_kwargs['check_function'] == mock_workbench.check_report_generation_status
    assert wait_kwargs['check_args']['process_id'] == 54321
    assert wait_kwargs['check_args']['scope'] == 'scan'
    assert wait_kwargs['check_args']['scan_code'] == 'SC'

    mock_download.assert_not_called()

# --- test global scan resolution ---
@patch('workbench_agent.handlers._resolve_project') # Still need to patch this even if not called directly
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.list_scans') # Mock the list_scans used for project lookup
@patch('os.makedirs')
@patch('workbench_agent.handlers.Workbench.generate_report')
@patch('workbench_agent.handlers._save_report_content')
def test_handle_download_reports_scan_global_resolve(mock_save, mock_gen_report, mock_makedirs, mock_list_scans_lookup, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests downloading report for a scan resolved globally (no project name provided)."""
    mock_params.command = 'download-reports'; mock_params.project_name = None; mock_params.scan_name = "GlobalScan" # No project name
    mock_params.report_scope = 'scan'; mock_params.report_type = 'json'; mock_params.report_save_path = "/out"
    mock_params.selection_type=None; mock_params.selection_view=None; mock_params.disclaimer=None; mock_params.include_vex=True
    # _resolve_scan finds the scan globally
    mock_resolve_scan.return_value = ("GLOBAL_SC", 999)
    # list_scans (used for project lookup) returns the scan with project context
    mock_list_scans_lookup.return_value = [
        {"name": "OtherScan", "code": "OSC", "id": "111", "project_code": "OTHER_PC"},
        {"name": "GlobalScan", "code": "GLOBAL_SC", "id": "999", "project_code": "FOUND_PC"} # Found project code
    ]
    mock_response = MagicMock(spec=requests.Response)
    mock_response.headers = {'content-type': 'application/json'}
    mock_gen_report.return_value = mock_response

    handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_not_called() # _resolve_project not called directly
    mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name="GlobalScan", project_name=None, create_if_missing=False, params=mock_params) # Global resolve
    mock_list_scans_lookup.assert_called_once_with() # list_scans called for project lookup
    mock_makedirs.assert_called_once_with("/out", exist_ok=True)
    # Check generate_report uses the looked-up project_code
    mock_gen_report.assert_called_once_with(scope='scan', project_code='FOUND_PC', scan_code='GLOBAL_SC', report_type='json', selection_type=None, selection_view=None, disclaimer=None, include_vex=True)
    mock_save.assert_called_once_with(mock_response, "/out", report_scope='scan', name_component='GlobalScan', report_type='json')

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.list_scans', return_value=[]) # Mock list_scans used for project lookup
def test_handle_download_reports_scan_global_resolve_project_fail(mock_list_scans_lookup, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure when project context cannot be found for a globally resolved scan."""
    mock_params.command = 'download-reports'; mock_params.project_name = None; mock_params.scan_name = "GlobalScan"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'json'
    mock_resolve_scan.return_value = ("GLOBAL_SC", 999) # Scan resolves globally

    with pytest.raises(ProjectNotFoundError, match="Could not determine project context for globally found scan 'GLOBAL_SC'"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_scan.assert_called_once()
    mock_list_scans_lookup.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
def test_handle_download_reports_invalid_scope(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests error when invalid report scope is provided."""
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'invalid_scope' # Invalid scope

    with pytest.raises(ValidationError, match="Invalid report scope: invalid_scope"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_not_called() # Should fail before resolving
    mock_resolve_scan.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
def test_handle_download_reports_invalid_type(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests error when invalid report type is provided."""
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'invalid_type,html' # One invalid type
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    # Get allowed types to construct the error message accurately
    allowed_types_str = ', '.join(sorted(list(Workbench.SCAN_REPORT_TYPES)))
    with pytest.raises(ValidationError, match=f"Invalid report type\\(s\\) for 'scan' scope: invalid_type. Allowed types are: {allowed_types_str}"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once() # Resolves project/scan before checking types
    mock_resolve_scan.assert_called_once()

# --- Project/Scan resolve failure tests ---
@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("Proj Not Found"))
@patch('workbench_agent.handlers._resolve_scan')
def test_handle_download_reports_project_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "ProjA"; mock_params.scan_name = "Scan1"; mock_params.report_scope = 'scan'
    with pytest.raises(ProjectNotFoundError, match="Proj Not Found"):
        handlers.handle_download_reports(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("Scan Not Found"))
def test_handle_download_reports_scan_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "ProjA"; mock_params.scan_name = "Scan1"; mock_params.report_scope = 'scan'
    mock_resolve_proj.return_value = "PROJ_A_CODE"
    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_download_reports(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()