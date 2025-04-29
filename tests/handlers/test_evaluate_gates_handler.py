# tests/handlers/test_evaluate_gates_handler.py

import pytest
from unittest.mock import MagicMock, patch

# Import handler and dependencies
from workbench_agent import handlers
from workbench_agent.exceptions import (
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ApiError, # Added for testing API errors during checks
    NetworkError # Added for testing Network errors during checks
)
# Import Workbench for type hinting
from workbench_agent.api import Workbench

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected function name
def test_handle_evaluate_gates_pass(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for PASS scenario
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "ProjB"; mock_params.scan_name = "ScanClean"
    mock_params.fail_on = 'both' # Assume default fail condition
    mock_resolve_proj.return_value = "PROJ_B_CODE"
    mock_resolve_scan.return_value = ("SCAN_CLEAN_CODE", 456)
    mock_get_status.return_value = {"progress_state": "FINISHED"} # Scan is finished
    mock_get_pending.return_value = {} # No pending files
    mock_get_policy.return_value = [] # No policy violations

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is True # Should return True for PASS
    mock_resolve_proj.assert_called_once_with(mock_workbench, "ProjB", create_if_missing=False)
    mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name="ScanClean", project_name="ProjB", create_if_missing=False, params=mock_params)
    mock_get_status.assert_called_once_with("SCAN", "SCAN_CLEAN_CODE")
    mock_wait.assert_not_called() # Not called if already finished
    mock_get_pending.assert_called_once_with("SCAN_CLEAN_CODE")
    mock_get_policy.assert_called_once_with("SCAN_CLEAN_CODE")

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_pass_needs_wait(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Test PASS scenario where scan needs waiting."""
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'both'
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    # Simulate scan running then finishing
    mock_get_status.side_effect = [
        {"progress_state": "RUNNING"}, # First check
        {"progress_state": "FINISHED"} # Check after wait
    ]
    mock_get_pending.return_value = {}
    mock_get_policy.return_value = []

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is True
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    assert mock_get_status.call_count == 2 # Called before and after wait
    mock_wait.assert_called_once_with("SCAN", "SC", mock_params.scan_number_of_tries, mock_params.scan_wait_time) # Wait is called
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_fail_pending(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (pending files)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'pending' # Fail on pending
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_get_status.return_value = {"progress_state": "FINISHED"}
    mock_get_pending.return_value = {"1": "/file/a"} # PENDING FILES FOUND
    mock_get_policy.return_value = [] # No policy violations

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should return False for FAIL
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_get_status.assert_called_once()
    mock_wait.assert_not_called()
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once() # Policy check should still happen

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_fail_policy(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (policy violations)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'policy' # Fail on policy
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_get_status.return_value = {"progress_state": "FINISHED"}
    mock_get_pending.return_value = {} # No pending
    mock_get_policy.return_value = [{"level": "HIGH", "count": 1}] # POLICY VIOLATION FOUND

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should return False for FAIL
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_get_status.assert_called_once()
    mock_wait.assert_not_called()
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_pass_with_pending_fail_on_policy(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Test that pending files don't cause failure if fail_on is 'policy'."""
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'policy' # ONLY fail on policy
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_get_status.return_value = {"progress_state": "FINISHED"}
    mock_get_pending.return_value = {"1": "/file/a"} # Pending files found
    mock_get_policy.return_value = [] # No policy violations

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is True # Should PASS because fail_on is 'policy'

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_pass_with_policy_fail_on_pending(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Test that policy violations don't cause failure if fail_on is 'pending'."""
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'pending' # ONLY fail on pending
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_get_status.return_value = {"progress_state": "FINISHED"}
    mock_get_pending.return_value = {} # No pending files
    mock_get_policy.return_value = [{"level": "HIGH", "count": 1}] # Policy violations found

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is True # Should PASS because fail_on is 'pending'

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish', side_effect=ProcessTimeoutError("Scan Timed Out"))
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_fail_scan_wait(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (scan wait fails)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'both'
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_get_status.return_value = {"progress_state": "RUNNING"} # Needs wait

    # Expect the underlying exception to propagate
    with pytest.raises(ProcessTimeoutError, match="Scan Timed Out"):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_get_status.assert_called_once() # Initial status check
    mock_wait.assert_called_once() # Wait is called and raises error
    mock_get_pending.assert_not_called()
    mock_get_policy.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status', return_value={"progress_state": "FAILED"}) # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_fail_scan_failed_status(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Test gate failure if initial scan status is FAILED."""
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'both'
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should fail if scan status is FAILED
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_get_status.assert_called_once()
    mock_wait.assert_not_called() # No wait if already failed
    mock_get_pending.assert_not_called() # No checks if scan failed
    mock_get_policy.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files', side_effect=ApiError("Pending check failed"))
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_fail_api_error_pending(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Test gate failure if API error occurs during pending check (and fail_on includes pending)."""
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'pending' # Fail if pending check fails
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_get_status.return_value = {"progress_state": "FINISHED"}

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should fail because check failed and fail_on includes pending
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once() # Policy check still attempted

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.get_scan_status') # Added
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files', side_effect=ApiError("Pending check failed"))
@patch('workbench_agent.handlers.Workbench.get_policy_violations') # Corrected
def test_handle_evaluate_gates_pass_api_error_pending_fail_on_none(mock_get_policy, mock_get_pending, mock_wait, mock_get_status, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Test gate passes if API error occurs during pending check but fail_on is 'none'."""
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.fail_on = 'none' # Do not fail on API errors
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_get_status.return_value = {"progress_state": "FINISHED"}
    mock_get_policy.return_value = [] # Assume policy check succeeds

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is True # Should pass because fail_on is 'none'
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once()

# --- Project/Scan resolve failure tests ---
@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("Proj Not Found"))
@patch('workbench_agent.handlers._resolve_scan')
def test_handle_evaluate_gates_project_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "ProjA"; mock_params.scan_name = "Scan1"
    with pytest.raises(ProjectNotFoundError, match="Proj Not Found"):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("Scan Not Found"))
def test_handle_evaluate_gates_scan_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "ProjA"; mock_params.scan_name = "Scan1"
    mock_resolve_proj.return_value = "PROJ_A_CODE"
    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()

