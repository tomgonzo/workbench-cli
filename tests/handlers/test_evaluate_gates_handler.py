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
    ProjectNotFoundError,
    ScanNotFoundError
)
# Import Workbench for type hinting
from workbench_cli.api import WorkbenchAPI

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

def test_handle_evaluate_gates_pass(monkeypatch, mock_workbench, mock_params):
    """Test passing gate check with all conditions in good state."""
    # Setup mocks for PASS scenario
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "ProjB"
    mock_params.scan_name = "ScanClean"
    mock_params.fail_on_pending = True
    mock_params.fail_on_policy = True
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PROJ_B_CODE")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SCAN_CLEAN_CODE", 456))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # No pending files
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {})
    
    # No policy warnings
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    )
    
    # No vulnerabilities
    monkeypatch.setattr(mock_workbench, 'list_vulnerabilities', lambda *args, **kwargs: [])

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True # Should return True for PASS

def test_handle_evaluate_gates_pass_needs_wait(monkeypatch, mock_workbench, mock_params):
    """Test passing gate check where scan needs waiting."""
    # Setup mocks for passing scenario with wait
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True
    mock_params.fail_on_policy = True
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
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
            
    monkeypatch.setattr(mock_workbench, 'get_scan_status', mock_get_status)
    
    # Mock wait_for_scan_to_finish to do nothing (just simulates waiting)
    monkeypatch.setattr(mock_workbench, 'wait_for_scan_to_finish', lambda *args, **kwargs: None)
    
    # No pending files
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {})
    
    # No policy warnings
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    )
    
    # No vulnerabilities
    monkeypatch.setattr(mock_workbench, 'list_vulnerabilities', lambda *args, **kwargs: [])

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True  # Should PASS after waiting

def test_handle_evaluate_gates_fail_pending(monkeypatch, mock_workbench, mock_params):
    """Test failing gate check due to pending files."""
    # Setup mocks for FAIL scenario (pending files)
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True  # Fail on pending
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # HAS pending files to trigger failure
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {"1": "/file/a"})
    
    # No policy warnings
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    )
    
    # No vulnerabilities
    monkeypatch.setattr(mock_workbench, 'list_vulnerabilities', lambda *args, **kwargs: [])

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False  # Should FAIL because of pending files

def test_handle_evaluate_gates_fail_policy(monkeypatch, mock_workbench, mock_params):
    """Test failing gate check due to policy violations."""
    # Setup mocks for FAIL scenario (policy violations)
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = True  # Fail on policy
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # No pending files
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {})
    
    # HAS policy warnings to trigger failure
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 5, "identified_files_with_warnings": 2, "dependencies_with_warnings": 3}
    )
    
    # No vulnerabilities
    monkeypatch.setattr(mock_workbench, 'list_vulnerabilities', lambda *args, **kwargs: [])

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False  # Should FAIL because of policy violations

def test_handle_evaluate_gates_pass_with_pending_fail_on_policy(monkeypatch, mock_workbench, mock_params):
    """Test that pending files don't cause failure if fail_on is 'policy'."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False  # Don't fail on pending
    mock_params.fail_on_policy = True  # ONLY fail on policy
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # HAS pending files but shouldn't fail
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {"1": "/file/a"})
    
    # No policy warnings (which would cause failure)
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    )
    
    # No vulnerabilities
    monkeypatch.setattr(mock_workbench, 'list_vulnerabilities', lambda *args, **kwargs: [])

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True  # Should PASS despite pending files

def test_handle_evaluate_gates_pass_with_policy_fail_on_pending(monkeypatch, mock_workbench, mock_params):
    """Test that policy violations don't cause failure if fail_on is 'pending'."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True  # ONLY fail on pending
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # No pending files (which would cause failure)
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {})
    
    # HAS policy warnings but shouldn't fail
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 5, "identified_files_with_warnings": 2, "dependencies_with_warnings": 3}
    )
    
    # No vulnerabilities
    monkeypatch.setattr(mock_workbench, 'list_vulnerabilities', lambda *args, **kwargs: [])

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True  # Should PASS despite policy violations

def test_handle_evaluate_gates_fail_scan_wait(monkeypatch, mock_workbench, mock_params):
    """Test failing gate check due to scan wait timeout."""
    # Setup mocks for FAIL scenario (scan wait fails)
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True
    mock_params.fail_on_policy = True
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Mock get_scan_status to always return RUNNING
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: {"status": "RUNNING"})
    
    # Make wait_for_scan_to_finish raise the exception
    def mock_wait_raises(*args, **kwargs):
        raise ProcessError("Scan Timed Out")
    
    monkeypatch.setattr(mock_workbench, 'wait_for_scan_to_finish', mock_wait_raises)
    
    # Handler should catch exception and return False
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False  # Should return False when timeout occurs

def test_handle_evaluate_gates_fail_scan_failed_status(monkeypatch, mock_workbench, mock_params):
    """Test gate failure if initial scan status is FAILED."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True
    mock_params.fail_on_policy = True
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status shows FAILED
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: {"status": "FAILED"})

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False  # Should FAIL because scan status is FAILED

def test_handle_evaluate_gates_fail_api_error_pending(monkeypatch, mock_workbench, mock_params):
    """Test that API errors during pending check cause FAIL with default settings."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = True
    mock_params.fail_on_policy = True
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # Pending check raises API error
    def mock_pending_that_raises(*args, **kwargs):
        raise ApiError("Pending check failed")
    
    monkeypatch.setattr(mock_workbench, 'get_pending_files', mock_pending_that_raises)
    
    # No policy warnings
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    )

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False  # Should FAIL because of API error in check

def test_handle_evaluate_gates_pass_api_error_pending_fail_on_none(monkeypatch, mock_workbench, mock_params):
    """Test that API errors during pending check are ignored if no failure conditions set."""
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # Pending check raises API error
    def mock_pending_that_raises(*args, **kwargs):
        raise ApiError("Pending check failed")
    
    monkeypatch.setattr(mock_workbench, 'get_pending_files', mock_pending_that_raises)
    
    # Policy violations exist but should be ignored
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 5, "identified_files_with_warnings": 2, "dependencies_with_warnings": 3}
    )

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True  # Should PASS because fail_on is not enabled

@patch('workbench_cli.handlers.evaluate_gates._resolve_project', side_effect=ProjectNotFoundError("Project 'ProjA' not found and creation was not requested."))
@patch('workbench_cli.handlers.evaluate_gates._resolve_scan')
def test_handle_evaluate_gates_project_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "ProjA"; mock_params.scan_name = "ScanA"
    with pytest.raises(ProjectNotFoundError, match="Project 'ProjA' not found and creation was not requested."):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()

@patch('workbench_cli.handlers.evaluate_gates._resolve_project')
@patch('workbench_cli.handlers.evaluate_gates._resolve_scan', side_effect=ScanNotFoundError("Scan Not Found"))
def test_handle_evaluate_gates_scan_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "ProjA"; mock_params.scan_name = "ScanA"
    mock_resolve_proj.return_value = "PROJ_A_CODE"
    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()

def test_handle_evaluate_gates_fail_vulnerabilities(monkeypatch, mock_workbench, mock_params):
    """Test failing gate check due to vulnerabilities."""
    # Setup mocks for FAIL scenario (vulnerabilities)
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = "high"  # Fail on high or critical
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # No pending files
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {})
    
    # No policy warnings
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    )
    
    # HAS vulnerabilities to trigger failure
    monkeypatch.setattr(
        mock_workbench, 
        'list_vulnerabilities', 
        lambda *args, **kwargs: [
            {"severity": "high", "id": "CVE-2022-1234", "component": "test-component"},
            {"severity": "medium", "id": "CVE-2022-5678", "component": "test-component"},
        ]
    )

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is False  # Should FAIL because of high vulnerability

def test_handle_evaluate_gates_pass_low_vulnerabilities(monkeypatch, mock_workbench, mock_params):
    """Test passing gate check with lower severity vulnerabilities."""
    # Setup mocks for PASS scenario (only low vulnerabilities, threshold is high)
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = "high"  # Only fail on high or critical
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # No pending files
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {})
    
    # No policy warnings
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    )
    
    # HAS vulnerabilities but only medium and low (below threshold)
    monkeypatch.setattr(
        mock_workbench, 
        'list_vulnerabilities', 
        lambda *args, **kwargs: [
            {"severity": "medium", "id": "CVE-2022-1234", "component": "test-component"},
            {"severity": "low", "id": "CVE-2022-5678", "component": "test-component"},
        ]
    )

    # Run handler
    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
    assert result is True  # Should PASS because vulnerabilities are below threshold

def test_handle_evaluate_gates_warn_vulnerabilities_no_fail_flag(monkeypatch, mock_workbench, mock_params):
    """Test warning but not failing when vulnerabilities exist but no fail flag is set."""
    # Setup mocks for warn scenario (vulnerabilities but no fail flag)
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.fail_on_pending = False
    mock_params.fail_on_policy = False
    mock_params.fail_on_vuln_severity = None  # No vulnerability threshold set
    mock_params.show_pending_files = False
    
    # Setup monkeypatching
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_project', lambda wb, pn, **kwargs: "PC")
    monkeypatch.setattr(handlers.evaluate_gates, '_resolve_scan', lambda wb, **kwargs: ("SC", 1))
    
    # Scan status
    scan_status_results = {"status": "FINISHED"}
    monkeypatch.setattr(mock_workbench, 'get_scan_status', lambda *args, **kwargs: scan_status_results)
    
    # No pending files
    monkeypatch.setattr(mock_workbench, 'get_pending_files', lambda *args, **kwargs: {})
    
    # No policy warnings
    monkeypatch.setattr(
        mock_workbench, 
        'get_policy_warnings_counter', 
        lambda *args, **kwargs: {"policy_warnings_total": 0, "identified_files_with_warnings": 0, "dependencies_with_warnings": 0}
    )
    
    # HAS critical vulnerabilities, but no fail flag set
    monkeypatch.setattr(
        mock_workbench, 
        'list_vulnerabilities', 
        lambda *args, **kwargs: [
            {"severity": "critical", "id": "CVE-2022-1234", "component": "test-component"},
            {"severity": "high", "id": "CVE-2022-5678", "component": "test-component"},
        ]
    )

    # Run handler with capturing stdout to check for warning message
    with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
        result = handlers.handle_evaluate_gates(mock_workbench, mock_params)
        output = mock_stdout.getvalue()
        assert "⚠️ Warning: Found 2 vulnerabilities" in output
        assert "Note: Gate is not set to fail on vulnerabilities" in output
    
    assert result is True  # Should PASS despite critical vulnerabilities because no fail flag

