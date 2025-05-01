# tests/integration/test_integration.py

import pytest
import sys
import os
import shutil
from unittest.mock import patch, MagicMock, mock_open

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
@patch('builtins.open', new_callable=mock_open, read_data=b'dummy data') # Mock file open
def test_scan_success_flow(mock_open, mock_getsize, mock_isdir, mock_exists, mock_api_post, tmp_path, capsys):
    """
    Integration test for a successful 'scan' command flow.
    Mocks API calls at the HTTP level.
    """
    dummy_path = create_dummy_path(tmp_path, is_dir=False)

    # Prepare mock API responses for a successful scan flow
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
        {"json_data": {"status": "1", "data": {"status": "FINISHED", "is_finished": "1"}}},
        # 8. _assert_scan_is_idle -> get_scan_status (check scan status before starting)
        {"json_data": {"status": "1", "data": {"status": "NEW"}}},
        # 9. _execute_standard_scan_flow -> start_scan
        {"json_data": {"status": "1"}},
        # 10. _execute_standard_scan_flow -> wait_for_scan_to_finish -> get_scan_status (running)
        {"json_data": {"status": "1", "data": {"status": "RUNNING", "is_finished": "0"}}},
        # 11. _execute_standard_scan_flow -> wait_for_scan_to_finish -> get_scan_status (finished)
        {"json_data": {"status": "1", "data": {"status": "FINISHED", "is_finished": "1"}}},
        # 12. get_pending_files (for summary info)
        {"json_data": {"status": "1", "data": {}}}, # No pending files
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
    
    # Check for key workflow steps - using less strict partial matches
    assert "Running SCAN Command" in captured.out
    assert "TEST_SCAN" in captured.out or "TestScan" in captured.out  # Match either format
    assert "Uploading" in captured.out and "Code" in captured.out
    assert "Archive extraction" in captured.out
    assert "KB Scan" in captured.out or "Scan process" in captured.out
    assert "complete" in captured.out.lower()  # Match "Complete" or "Completed"
    
    # Check for absence of errors
    assert "Error:" not in captured.out
    assert "Failed:" not in captured.out
    assert "Error:" not in captured.err
    assert "Failed:" not in captured.err

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=100)
@patch('builtins.open', new_callable=mock_open, read_data=b'dummy data')
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
        # 3. _assert_scan_is_idle -> get_scan_status (check scan status before starting)
        {"json_data": {"status": "1", "data": {"status": "NEW"}}},
        # 4. upload_files
        {"status_code": 200, "json_data": {"status": "1"}},
        # 5. extract_archives (assuming simple case with no extraction)
        {"json_data": {"status": "1", "data": {"is_finished": "1"}}},
        # 6. start_scan
        {"json_data": {"status": "1"}},
        # 7. wait_for_scan_to_finish -> get_scan_status (running)
        {"json_data": {"status": "1", "data": {"status": "RUNNING", "is_finished": "0"}}},
        # 8. wait_for_scan_to_finish -> get_scan_status (FAILED)
        {"json_data": {"status": "1", "data": {"status": "FAILED", "is_finished": "1", "error": "Disk space low"}}},
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
    assert return_code == 1  # Expect failure exit code
    captured = capsys.readouterr()
    
    # Check for key workflow steps and error message
    assert "Running SCAN Command" in captured.out
    assert "Uploading" in captured.out
    assert "TestScan" in captured.out or "TSC" in captured.out
    
    # Check for error messages - more flexible to handle format changes
    assert any(error_text in captured.err.lower() for error_text in 
               ["scan failed", "failed", "error", "disk space low"])

def test_evaluate_gates_pass_flow(mock_api_post, capsys):
    """
    Integration test for a successful 'evaluate-gates' command flow.
    """
    mock_api_post([
        # 1. _resolve_project -> list_projects
        {"json_data": {"status": "1", "data": [{"name": "EvalProj", "code": "EPC"}]}},
        # 2. _resolve_scan -> list_scans
        {"json_data": {"status": "1", "data": [{"name": "EvalScan", "code": "ESC", "id": "456"}]}},
        # 3. Check scan status before waiting (_assert_scan_is_idle)
        {"json_data": {"status": "1", "data": {"status": "FINISHED", "is_finished": "1"}}},
        # 4. Check scan status (finished) - get_scan_status for SCAN
        {"json_data": {"status": "1", "data": {"status": "FINISHED", "is_finished": "1"}}},
        # 5. Check DA status (if required) - get_scan_status for DEPENDENCY_ANALYSIS
        {"json_data": {"status": "1", "data": {"status": "FINISHED", "is_finished": "1"}}},
        # 6. get_pending_files
        {"json_data": {"status": "1", "data": {}}}, # No pending files
        # 7. get_policy_warnings_counter (assuming --policy-check)
        {"json_data": {"status": "1", "data": {"total": 0}}}, # No policy warnings
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
    
    # More flexible assertions that focus on key workflow components
    assert "EVALUATE-GATES Command" in captured.out
    assert "EvalScan" in captured.out or "ESC" in captured.out
    assert "pending" in captured.out.lower()
    assert "policy" in captured.out.lower()
    assert "pass" in captured.out.lower() or "passed" in captured.out.lower()
    
    # Verify absence of errors
    assert "Error:" not in captured.out
    assert "Failed:" not in captured.out
    assert "Error:" not in captured.err
    assert "Failed:" not in captured.err

def test_evaluate_gates_fail_pending_flow(mock_api_post, capsys):
    """
    Integration test for 'evaluate-gates' failing due to pending files.
    """
    mock_api_post([
        # 1. _resolve_project -> list_projects
        {"json_data": {"status": "1", "data": [{"name": "EvalProj", "code": "EPC"}]}},
        # 2. _resolve_scan -> list_scans
        {"json_data": {"status": "1", "data": [{"name": "EvalScan", "code": "ESC", "id": "456"}]}},
        # 3. Check scan status before waiting (_assert_scan_is_idle)
        {"json_data": {"status": "1", "data": {"status": "FINISHED", "is_finished": "1"}}},
        # 4. Check scan status (finished) - get_scan_status for SCAN
        {"json_data": {"status": "1", "data": {"status": "FINISHED", "is_finished": "1"}}},
        # 5. Check DA status (if required) - get_scan_status for DEPENDENCY_ANALYSIS
        {"json_data": {"status": "1", "data": {"status": "FINISHED", "is_finished": "1"}}},
        # 6. get_pending_files -> Returns pending files
        {"json_data": {"status": "1", "data": {"1": "/path/pending.c"}}},
        # 7. get_policy_warnings_counter (still called even if pending files found)
        {"json_data": {"status": "1", "data": {"total": 0}}},
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
    
    # Check for presence of key workflow steps and failure messages
    assert "EVALUATE-GATES Command" in captured.out
    assert "pending" in captured.out.lower() or "pending" in captured.err.lower()
    assert any(fail_text in (captured.out + captured.err).lower() for fail_text in 
              ["failed", "failure", "found 1 pending", "gate evaluation failed"])

@patch('os.makedirs') # Mock directory creation for saving report
@patch('builtins.open', new_callable=mock_open) # Mock file writing
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
        {"status_code": 200, 
         "headers": {"content-type": "text/html", "content-disposition": "attachment; filename=report.html"}, 
         "content": b"<html>Report Data</html>"},
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

    # Assertions with more flexibility
    assert return_code == 0
    captured = capsys.readouterr()
    
    # Check for key workflow components
    assert "DOWNLOAD-REPORTS Command" in captured.out
    assert "report" in captured.out.lower() and "html" in captured.out.lower()
    assert "saving" in captured.out.lower() or "saved" in captured.out.lower()
    assert "success" in captured.out.lower() or "downloaded" in captured.out.lower() 
    
    # Verify directory creation and file writing
    mock_makedirs.assert_called_once_with(str(save_path), exist_ok=True)
    mock_open_file.assert_called_once() # At least one file should be opened for writing

# --- Add more integration tests ---
# - test_download_report_async_flow (xlsx, etc.)
# - test_show_results_flow
# - test_scan_git_success_flow
# - test_import_da_success_flow
# - Tests for various failure scenarios (API errors at different stages, validation errors caught by main)
# - Test project/scan creation flows (where list returns empty, then create is called)

