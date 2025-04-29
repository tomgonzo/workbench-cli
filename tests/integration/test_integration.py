# tests/integration/test_integration.py

import pytest
import sys
import os
import shutil
from unittest.mock import patch, MagicMock

# Import the main entry point of your application
from workbench_agent.main import main # Correct import
from workbench_agent.cli import parse_cmdline_args # Keep this if testing parsing separately

# --- Helper Function to Create Dummy Files/Dirs ---
def create_dummy_path(tmp_path, is_dir=False, content="dummy content"):
    path = tmp_path / ("dummy_dir" if is_dir else "dummy_file.zip")
    if is_dir:
        path.mkdir()
        (path / "file_inside.txt").write_text(content)
    else:
        path.write_text(content)
    return str(path)

# --- Integration Tests ---

@patch('os.path.exists', return_value=True) # Assume path exists for upload
@patch('os.path.isdir', return_value=False) # Assume it's a file
@patch('os.path.getsize', return_value=100) # Assume small file size
@patch('builtins.open', new_callable=patch.mock_open, read_data=b'dummy data') # Mock file open
def test_scan_success_flow(mock_open, mock_getsize, mock_isdir, mock_exists, mock_api_post, tmp_path, capsys):
    """
    Integration test for a successful 'scan' command flow.
    Mocks API calls at the HTTP level.
    """
    dummy_path = create_dummy_path(tmp_path, is_dir=False)

    # Define the sequence of expected API responses for this flow
    mock_api_post([
        # 1. _resolve_project -> list_projects (assume project exists)
        {"json_data": {"status": "1", "data": [{"name": "TestProj", "code": "TPC"}]}},
        # 2. _resolve_scan -> list_scans (assume scan exists)
        {"json_data": {"status": "1", "data": [{"name": "TestScan", "code": "TSC", "id": "123"}]}},
        # 3. _ensure_scan_compatibility (no API call needed if not git/DA)
        # 4. upload_files (POST request, simple success response)
        {"status_code": 200, "json_data": {"status": "1"}}, # Simulate successful upload
        # 5. extract_archives (assuming --recursively-extract-archives is used)
        {"json_data": {"status": "1"}},
        # 6. _is_status_check_supported (for extraction)
        {"json_data": {"status": "1"}},
        # 7. wait_for_archive_extraction -> get_scan_status (check extraction status)
        {"json_data": {"status": "1", "data": {"status": "FINISHED"}}},
        # 8. _execute_standard_scan_flow -> start_scan
        {"json_data": {"status": "1"}},
        # 9. _execute_standard_scan_flow -> wait_for_scan_to_finish -> get_scan_status (running)
        {"json_data": {"status": "1", "data": {"status": "RUNNING"}}},
        # 10. _execute_standard_scan_flow -> wait_for_scan_to_finish -> get_scan_status (finished)
        {"json_data": {"status": "1", "data": {"status": "FINISHED"}}},
        # 11. fetch_and_process_results (if show flags were used - not in this basic scan)
        #     -> get_scan_results / get_scan_identified_components etc.
    ])

    # Prepare command line arguments
    args = [
        'workbench-agent',
        '--api-url', 'http://dummy.com',
        '--api-user', 'test',
        '--api-token', 'token',
        'scan',
        '--project-name', 'TestProj',
        '--scan-name', 'TestScan',
        '--path', dummy_path,
        '--recursively-extract-archives' # Include to test extraction flow
    ]

    with patch.object(sys, 'argv', args):
        return_code = main()

    # Assertions
    assert return_code == 0
    captured = capsys.readouterr()
    assert "Starting scan..." in captured.out # Check for expected log messages
    assert "Waiting for scan TestScan to finish..." in captured.out
    assert "Scan finished successfully." in captured.out
    assert "Error" not in captured.err # Check for unexpected errors

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=100)
@patch('builtins.open', new_callable=patch.mock_open, read_data=b'dummy data')
def test_scan_fail_during_scan(mock_open, mock_getsize, mock_isdir, mock_exists, mock_api_post, tmp_path, capsys):
    """
    Integration test for a 'scan' command that fails during the scan phase.
    """
    dummy_path = create_dummy_path(tmp_path, is_dir=False)

    mock_api_post([
        # 1. _resolve_project -> list_projects
        {"json_data": {"status": "1", "data": [{"name": "TestProj", "code": "TPC"}]}},
        # 2. _resolve_scan -> list_scans
        {"json_data": {"status": "1", "data": [{"name": "TestScan", "code": "TSC", "id": "123"}]}},
        # 3. upload_files
        {"status_code": 200, "json_data": {"status": "1"}},
        # 4. start_scan
        {"json_data": {"status": "1"}},
        # 5. wait_for_scan_to_finish -> get_scan_status (running)
        {"json_data": {"status": "1", "data": {"status": "RUNNING"}}},
        # 6. wait_for_scan_to_finish -> get_scan_status (FAILED)
        {"json_data": {"status": "1", "data": {"status": "FAILED", "error_message": "Disk space low"}}},
    ])

    args = [
        'workbench-agent',
        '--api-url', 'http://dummy.com',
        '--api-user', 'test',
        '--api-token', 'token',
        'scan',
        '--project-name', 'TestProj',
        '--scan-name', 'TestScan',
        '--path', dummy_path,
        # No extraction args for simplicity
    ]

    with patch.object(sys, 'argv', args):
        return_code = main()

    # Assertions
    assert return_code == 1 # Expect failure exit code
    captured = capsys.readouterr()
    assert "Waiting for scan TestScan to finish..." in captured.out
    assert "Scan failed." in captured.err # Error message should be printed
    assert "Disk space low" in captured.err # Specific error from API

def test_evaluate_gates_pass_flow(mock_api_post, capsys):
    """
    Integration test for a successful 'evaluate-gates' command flow.
    """
    mock_api_post([
        # 1. _resolve_project -> list_projects
        {"json_data": {"status": "1", "data": [{"name": "EvalProj", "code": "EPC"}]}},
        # 2. _resolve_scan -> list_scans
        {"json_data": {"status": "1", "data": [{"name": "EvalScan", "code": "ESC", "id": "456"}]}},
        # 3. generate_links (no API call, internal logic)
        # 4. set_env_variable (no API call)
        # 5. wait_for_scan_to_finish -> get_scan_status (assume already finished)
        {"json_data": {"status": "1", "data": {"status": "FINISHED"}}},
        # 6. get_pending_files
        {"json_data": {"status": "1", "data": {}}}, # No pending files
        # 7. get_policy_warnings_info (assuming --policy-check)
        {"json_data": {"status": "1", "data": {"policy_warnings_list": []}}}, # No policy warnings
    ])

    args = [
        'workbench-agent',
        '--api-url', 'http://dummy.com',
        '--api-user', 'test',
        '--api-token', 'token',
        'evaluate-gates',
        '--project-name', 'EvalProj',
        '--scan-name', 'EvalScan',
        '--policy-check' # Enable policy check
    ]

    with patch.object(sys, 'argv', args):
        return_code = main()

    # Assertions
    assert return_code == 0 # Success exit code
    captured = capsys.readouterr()
    assert "Waiting for scan EvalScan to finish..." in captured.out
    assert "Checking for pending files..." in captured.out
    assert "Checking policy warnings..." in captured.out
    assert "Gate evaluation passed." in captured.out
    assert "Error" not in captured.err

def test_evaluate_gates_fail_pending_flow(mock_api_post, capsys):
    """
    Integration test for 'evaluate-gates' failing due to pending files.
    """
    mock_api_post([
        # 1. _resolve_project -> list_projects
        {"json_data": {"status": "1", "data": [{"name": "EvalProj", "code": "EPC"}]}},
        # 2. _resolve_scan -> list_scans
        {"json_data": {"status": "1", "data": [{"name": "EvalScan", "code": "ESC", "id": "456"}]}},
        # 3. wait_for_scan_to_finish -> get_scan_status
        {"json_data": {"status": "1", "data": {"status": "FINISHED"}}},
        # 4. get_pending_files -> Returns pending files
        {"json_data": {"status": "1", "data": {"1": "/path/pending.c"}}},
        # 5. get_policy_warnings_info (still called even if pending files found)
        {"json_data": {"status": "1", "data": {"policy_warnings_list": []}}},
    ])

    args = [
        'workbench-agent',
        '--api-url', 'http://dummy.com',
        '--api-user', 'test',
        '--api-token', 'token',
        'evaluate-gates',
        '--project-name', 'EvalProj',
        '--scan-name', 'EvalScan',
        '--policy-check'
    ]

    with patch.object(sys, 'argv', args):
        return_code = main()

    # Assertions
    assert return_code == 1 # Failure exit code
    captured = capsys.readouterr()
    assert "Checking for pending files..." in captured.out
    assert "Found 1 pending file(s)." in captured.err # Error message for pending
    assert "Gate evaluation failed." in captured.err

@patch('os.makedirs') # Mock directory creation for saving report
@patch('builtins.open', new_callable=patch.mock_open) # Mock file writing
def test_download_report_sync_flow(mock_open_file, mock_makedirs, mock_api_post, tmp_path, capsys):
    """
    Integration test for downloading a synchronous report (e.g., HTML).
    """
    save_path = tmp_path / "reports"

    mock_api_post([
        # 1. _resolve_project -> list_projects
        {"json_data": {"status": "1", "data": [{"name": "ReportProj", "code": "RPC"}]}},
        # 2. _resolve_scan -> list_scans
        {"json_data": {"status": "1", "data": [{"name": "ReportScan", "code": "RSC", "id": "789"}]}},
        # 3. generate_report (sync) -> Returns report content directly
        {"status_code": 200, "headers": {"content-type": "text/html"}, "content": b"<html>Report Data</html>"},
    ])

    args = [
        'workbench-agent',
        '--api-url', 'http://dummy.com',
        '--api-user', 'test',
        '--api-token', 'token',
        'download-reports',
        '--project-name', 'ReportProj',
        '--scan-name', 'ReportScan',
        '--report-type', 'html',
        '--report-save-path', str(save_path)
    ]

    with patch.object(sys, 'argv', args):
        return_code = main()

    # Assertions
    assert return_code == 0
    captured = capsys.readouterr()
    assert "Generating report(s): html" in captured.out
    assert f"Saving report html to {save_path}" in captured.out
    assert "Report 'html' downloaded successfully" in captured.out
    mock_makedirs.assert_called_once_with(str(save_path), exist_ok=True)
    # Check that open was called with the correct path and mode
    mock_open_file.assert_called_once_with(os.path.join(str(save_path), 'ReportScan_scan_report.html'), 'wb')
    # Check that the correct content was written
    handle = mock_open_file()
    handle.write.assert_called_once_with(b"<html>Report Data</html>")

# --- Add more integration tests ---
# - test_download_report_async_flow (xlsx, etc.)
# - test_show_results_flow
# - test_scan_git_success_flow
# - test_import_da_success_flow
# - Tests for various failure scenarios (API errors at different stages, validation errors caught by main)
# - Test project/scan creation flows (where list returns empty, then create is called)

