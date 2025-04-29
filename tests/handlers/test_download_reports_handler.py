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
    ScanNotFoundError
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('os.makedirs')
@patch('workbench_agent.handlers.Workbench.generate_report')
@patch('workbench_agent.handlers._save_report_content')
def test_handle_download_reports_scan_sync(mock_save, mock_gen_report, mock_makedirs, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'html'; mock_params.report_save_path = "/out"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_response = MagicMock(spec=requests.Response) # Simulate sync response
    mock_response.headers = {'content-type': 'text/html'} # Needed for _save_report_content logic
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
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = None # Scan name not needed for project scope
    mock_params.report_scope = 'project'; mock_params.report_type = 'xlsx'; mock_params.report_save_path = "/out"
    mock_resolve_proj.return_value = "PC"
    # _resolve_scan should not be called for project scope
    mock_gen_report.return_value = 12345 # Simulate async process ID
    mock_download_response = MagicMock(spec=requests.Response)
    mock_download_response.headers = {'content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
    mock_download.return_value = mock_download_response

    handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once_with(mock_workbench, "P", create_if_missing=False)
    mock_resolve_scan.assert_not_called()
    mock_makedirs.assert_called_once_with("/out", exist_ok=True)
    mock_gen_report.assert_called_once_with(scope='project', project_code='PC', scan_code=None, report_type='xlsx', selection_type=None, selection_view=None, disclaimer=None, include_vex=True)
    # Check that waiting happened - args depend on how _wait_for_process is called internally
    mock_wait.assert_called_once()
    assert mock_wait.call_args[0][0] == "Report Generation (xlsx)" # Check description
    assert mock_wait.call_args[1]['check_args']['process_id'] == 12345 # Check process ID passed

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
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    # Simulate html (sync) succeeds, xlsx (async) wait fails
    mock_sync_response = MagicMock(spec=requests.Response)
    mock_sync_response.headers = {'content-type': 'text/html'}
    mock_wait.side_effect = ProcessError("Report generation failed") # Fail on the async wait

    mock_gen_report.side_effect = [
        mock_sync_response, # html succeeds (returns response)
        54321              # xlsx starts async (returns process ID)
    ]

    # Expect the handler to raise an exception because one report failed
    with pytest.raises(ProcessError, match="Failed to process one or more reports: xlsx"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_makedirs.assert_called_once()
    assert mock_gen_report.call_count == 2
    mock_gen_report.assert_has_calls([
        call(scope='scan', project_code='PC', scan_code='SC', report_type='html', selection_type=None, selection_view=None, disclaimer=None, include_vex=True),
        call(scope='scan', project_code='PC', scan_code='SC', report_type='xlsx', selection_type=None, selection_view=None, disclaimer=None, include_vex=True)
    ])
    mock_save.assert_called_once_with(mock_sync_response, "/out", report_scope='scan', name_component='S', report_type='html') # Only called for html
    mock_wait.assert_called_once() # Called for xlsx
    mock_download.assert_not_called() # Not called because wait failed

@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("Proj Not Found"))
@patch('workbench_agent.handlers._resolve_scan')
def test_handle_download_reports_project_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1" # Doesn't matter if project fails
    mock_params.report_scope = 'scan'

    with pytest.raises(ProjectNotFoundError, match="Proj Not Found"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("Scan Not Found"))
def test_handle_download_reports_scan_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.report_scope = 'scan' # Scan scope requires scan resolve
    mock_resolve_proj.return_value = "PROJ_A_CODE"

    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()

