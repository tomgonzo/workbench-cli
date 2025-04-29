# tests/handlers/test_evaluate_gates_handler.py

import pytest
from unittest.mock import MagicMock, patch

# Import handler and dependencies
from workbench_agent import handlers
from workbench_agent.exceptions import (
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.generate_links')
@patch('workbench_agent.handlers.Workbench.set_env_variable')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_warnings_info')
def test_handle_evaluate_gates_pass(mock_get_policy, mock_get_pending, mock_wait, mock_set_env, mock_gen_links, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for PASS scenario
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "ProjB"
    mock_params.scan_name = "ScanClean"
    mock_params.policy_check = True
    mock_resolve_proj.return_value = "PROJ_B_CODE"
    mock_resolve_scan.return_value = ("SCAN_CLEAN_CODE", 456)
    mock_gen_links.return_value = {"main_scan_link": "http://main", "pending_link": "http://pending", "policy_link": "http://policy"}
    mock_get_pending.return_value = {} # No pending files
    mock_get_policy.return_value = {"policy_warnings_list": []} # No policy violations

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is True # Should return True for PASS
    mock_resolve_proj.assert_called_once_with(mock_workbench, "ProjB", create_if_missing=False)
    mock_resolve_scan.assert_called_once_with(mock_workbench, scan_name="ScanClean", project_name="ProjB", create_if_missing=False, params=mock_params)
    mock_gen_links.assert_called_once_with(mock_params.api_url, 456)
    mock_set_env.assert_called_once_with("FOSSID_SCAN_URL", "http://main")
    mock_wait.assert_called_once_with("SCAN", "SCAN_CLEAN_CODE", mock_params.scan_number_of_tries, mock_params.scan_wait_time)
    mock_get_pending.assert_called_once_with("SCAN_CLEAN_CODE")
    mock_get_policy.assert_called_once_with("SCAN_CLEAN_CODE")

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.generate_links')
@patch('workbench_agent.handlers.Workbench.set_env_variable')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_warnings_info')
def test_handle_evaluate_gates_fail_pending(mock_get_policy, mock_get_pending, mock_wait, mock_set_env, mock_gen_links, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (pending files)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.policy_check = True # Check policy too
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_gen_links.return_value = {"main_scan_link": "http://main", "pending_link": "http://pending", "policy_link": "http://policy"}
    mock_get_pending.return_value = {"1": "/file/a"} # PENDING FILES FOUND
    mock_get_policy.return_value = {"policy_warnings_list": []} # No policy violations

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should return False for FAIL
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_wait.assert_called_once()
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once() # Policy check should still happen

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.generate_links')
@patch('workbench_agent.handlers.Workbench.set_env_variable')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_warnings_info')
def test_handle_evaluate_gates_fail_policy(mock_get_policy, mock_get_pending, mock_wait, mock_set_env, mock_gen_links, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (policy violations)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.policy_check = True
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_gen_links.return_value = {"main_scan_link": "http://main", "pending_link": "http://pending", "policy_link": "http://policy"}
    mock_get_pending.return_value = {} # No pending
    mock_get_policy.return_value = {"policy_warnings_list": [{"type": "license"}]} # POLICY VIOLATION FOUND

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should return False for FAIL
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_wait.assert_called_once()
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.generate_links')
@patch('workbench_agent.handlers.Workbench.set_env_variable')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish', side_effect=ProcessTimeoutError("Scan Timed Out"))
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_warnings_info')
def test_handle_evaluate_gates_fail_scan_wait(mock_get_policy, mock_get_pending, mock_wait, mock_set_env, mock_gen_links, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (scan wait fails)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.policy_check = True
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_gen_links.return_value = {"main_scan_link": "http://main", "pending_link": "http://pending", "policy_link": "http://policy"}

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should return False for FAIL
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_wait.assert_called_once()
    mock_get_pending.assert_not_called() # Should not check pending if wait fails
    mock_get_policy.assert_not_called() # Should not check policy if wait fails

@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("Proj Not Found"))
@patch('workbench_agent.handlers._resolve_scan')
def test_handle_evaluate_gates_project_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.policy_check = True

    with pytest.raises(ProjectNotFoundError, match="Proj Not Found"):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("Scan Not Found"))
def test_handle_evaluate_gates_scan_resolve_fails(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.policy_check = True
    mock_resolve_proj.return_value = "PROJ_A_CODE"

    with pytest.raises(ScanNotFoundError, match="Scan Not Found"):
        handlers.handle_evaluate_gates(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()

