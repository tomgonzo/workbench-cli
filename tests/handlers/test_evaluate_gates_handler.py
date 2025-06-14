# tests/handlers/test_evaluate_gates_handler.py

import pytest
from unittest.mock import MagicMock, patch, call
from io import StringIO

# Import handler and dependencies
from workbench_cli import handlers
from workbench_cli.exceptions import (
    WorkbenchCLIError,
    ApiError, 
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError
)
# Import Workbench for type hinting
from workbench_cli.api import WorkbenchAPI

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

def test_handle_evaluate_gates_pass(mock_workbench, mock_params):
    """Test passing gate check with all conditions in good state."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "ProjB"
    mock_params.scan_name = "ScanClean"
    mock_params.fail_on_pending = True
    mock_params.fail_on_policy = True
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PROJ_B_CODE"
    mock_workbench.resolve_scan.return_value = ("SCAN_CLEAN_CODE", 456)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.return_value = {}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    mock_workbench.list_vulnerabilities.return_value = []

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True # Should return True for PASS

def test_handle_evaluate_gates_pass_needs_wait(mock_workbench, mock_params):
    """Test passing gate check where scan needs waiting."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True
    mock_params.fail_on_policy = True
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    
    # Create a counter to track how many times get_scan_status is called,
    # returning RUNNING only the first time, then FINISHED
    status_call_count = [0]  # Use list for mutable state
    
    def mock_get_status(scan_type, scan_code):
        status_call_count[0] += 1
        # Only return RUNNING for the first call
        if status_call_count[0] == 1:
            return {"status": "RUNNING"}
        else:
            return {"status": "FINISHED"}
            
    mock_workbench.get_scan_status.side_effect = mock_get_status
    mock_workbench.wait_for_scan_to_finish.return_value = None
    mock_workbench.get_pending_files.return_value = {}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    mock_workbench.list_vulnerabilities.return_value = []

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True  # Should PASS after waiting

def test_handle_evaluate_gates_fail_pending(mock_workbench, mock_params):
    """Test failing gate check due to pending files."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True  # Fail on pending
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.return_value = {"1": "/file/a"}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    mock_workbench.list_vulnerabilities.return_value = []

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False  # Should FAIL because of pending files

def test_handle_evaluate_gates_fail_policy(mock_workbench, mock_params):
    """Test failing gate check due to policy violations."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = True  # Fail on policy
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.return_value = {}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 5, "identified_files_with_warnings": 2, "dependencies_with_warnings": 3}
    mock_workbench.list_vulnerabilities.return_value = []

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False  # Should FAIL because of policy violations

def test_handle_evaluate_gates_pass_with_pending_fail_on_policy(mock_workbench, mock_params):
    """Test that pending files don't cause failure if fail_on is 'policy'."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False  # Don't fail on pending
    mock_params.fail_on_policy = True  # ONLY fail on policy
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.return_value = {"1": "/file/a"}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    mock_workbench.list_vulnerabilities.return_value = []

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True  # Should PASS despite pending files

def test_handle_evaluate_gates_pass_with_policy_fail_on_pending(mock_workbench, mock_params):
    """Test that policy violations don't cause failure if fail_on is 'pending'."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True  # ONLY fail on pending
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.return_value = {}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 5, "identified_files_with_warnings": 2, "dependencies_with_warnings": 3}
    mock_workbench.list_vulnerabilities.return_value = []

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True  # Should PASS despite policy violations

def test_handle_evaluate_gates_fail_scan_wait(mock_workbench, mock_params):
    """Test failing gate check due to scan wait timeout."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "RUNNING"}
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Scan timed out")

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False

def test_handle_evaluate_gates_fail_scan_failed_status(mock_workbench, mock_params):
    """Test failing gate check due to scan status being 'FAILED'."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"

    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FAILED"}

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False

def test_handle_evaluate_gates_fail_api_error_pending(mock_workbench, mock_params):
    """Test that ApiError from get_pending_files is handled."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None
    
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.side_effect = ApiError("API error getting pending files")
    mock_workbench.get_policy_warnings_counter.return_value = {}
    mock_workbench.list_vulnerabilities.return_value = []

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False

def test_handle_evaluate_gates_pass_api_error_pending_fail_on_none(mock_workbench, mock_params):
    """Test that get_pending_files is not called if fail_on_pending is False."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None

    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 0}
    mock_workbench.list_vulnerabilities.return_value = []
    # This should still be called to check for pending files, even if we don't fail on them
    mock_workbench.get_pending_files.return_value = {}
    
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    
    assert result is True
    mock_workbench.get_pending_files.assert_called_once()

def test_handle_evaluate_gates_project_resolve_fails(mock_workbench, mock_params):
    """Tests that ProjectNotFoundError is raised when project resolution fails."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "non-existent"
    mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

    with pytest.raises(ProjectNotFoundError):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)

def test_handle_evaluate_gates_scan_resolve_fails(mock_workbench, mock_params):
    """Tests that ScanNotFoundError is raised when scan resolution fails."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "non-existent"
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Scan not found")

    with pytest.raises(ScanNotFoundError):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)

def test_handle_evaluate_gates_fail_vulnerabilities(mock_workbench, mock_params):
    """Test failing gate check due to high severity vulnerabilities."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = 'high' # Fail on high severity
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.return_value = {}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 0}
    
    # HAS vulnerabilities to trigger failure
    mock_workbench.list_vulnerabilities.return_value = [
        {"severity": "high", "id": "CVE-2022-1234", "component": "test-component"},
        {"severity": "medium", "id": "CVE-2022-5678", "component": "test-component"},
    ]

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False # Should FAIL

def test_handle_evaluate_gates_pass_low_vulnerabilities(mock_workbench, mock_params):
    """Test passing gate check when vulnerabilities are below the fail_on threshold."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = 'critical' # Fail on critical only
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.return_value = {}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 0}
    
    # Has vulnerabilities, but none are critical
    mock_workbench.list_vulnerabilities.return_value = [
        {"severity": "medium", "id": "CVE-2022-1234", "component": "test-component"},
        {"severity": "low", "id": "CVE-2022-5678", "component": "test-component"},
    ]

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True # Should PASS

def test_handle_evaluate_gates_warn_vulnerabilities_no_fail_flag(mock_workbench, mock_params):
    """Test that vulnerabilities cause a warning but not failure if fail_on is not set."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None # Don't fail on vulnerabilities
    mock_params.show_pending_files = False
    
    # Setup mocks
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.return_value = ("SC", 1)
    mock_workbench.get_scan_status.return_value = {"status": "FINISHED"}
    mock_workbench.get_pending_files.return_value = {}
    mock_workbench.get_policy_warnings_counter.return_value = {"policy_warnings_total": 0}

    # HAS vulnerabilities to trigger warning
    mock_workbench.list_vulnerabilities.return_value = [
        {"severity": "high", "cve": "CVE-2023-0001"}
    ]

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True # Should PASS, but with warnings printed

