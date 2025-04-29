# tests/handlers/test_scan_git_handler.py

import pytest
from unittest.mock import MagicMock, patch

# Import handler and dependencies
from workbench_agent import handlers
from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    CompatibilityError # Import needed for compatibility test
)

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._execute_standard_scan_flow') # Mock the whole flow utility
def test_handle_scan_git_success_branch(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution of handle_scan_git using a branch."""
    # Setup mock_params for scan-git with branch
    mock_params.command = 'scan-git'
    mock_params.project_name = "GitProjBranch"
    mock_params.scan_name = "GitScanBranch"
    mock_params.git_url = "http://my.git/repo.git"
    mock_params.git_branch = "main"
    mock_params.git_tag = None # Ensure tag is None
    mock_resolve_proj.return_value = "GIT_PROJ_B_C"
    mock_resolve_scan.return_value = ("GIT_SCAN_B_C", 567) # scan_code, scan_id

    # Call the handler
    handlers.handle_scan_git(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once_with(mock_workbench, "GitProjBranch", create_if_missing=True)
    # _resolve_scan handles creation/compatibility based on params
    mock_resolve_scan.assert_called_once_with(
        mock_workbench,
        scan_name="GitScanBranch",
        project_name="GitProjBranch",
        create_if_missing=True,
        params=mock_params # Pass params for git info and creation logic
    )
    # Assert the standard flow was executed after resolving project/scan
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "GIT_PROJ_B_C", "GIT_SCAN_B_C", 567)

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._execute_standard_scan_flow')
def test_handle_scan_git_success_tag(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution of handle_scan_git using a tag."""
    # Setup mock_params for scan-git with tag
    mock_params.command = 'scan-git'
    mock_params.project_name = "GitProjTag"
    mock_params.scan_name = "GitScanTag"
    mock_params.git_url = "http://my.git/repo.git"
    mock_params.git_branch = None # Ensure branch is None
    mock_params.git_tag = "v1.0.0"
    mock_resolve_proj.return_value = "GIT_PROJ_T_C"
    mock_resolve_scan.return_value = ("GIT_SCAN_T_C", 568)

    # Call the handler
    handlers.handle_scan_git(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once_with(mock_workbench, "GitProjTag", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench,
        scan_name="GitScanTag",
        project_name="GitProjTag",
        create_if_missing=True,
        params=mock_params
    )
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "GIT_PROJ_T_C", "GIT_SCAN_T_C", 568)

@patch('workbench_agent.handlers._resolve_project', side_effect=ProjectNotFoundError("Git project not found"))
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._execute_standard_scan_flow')
def test_handle_scan_git_project_not_found(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ProjectNotFoundError from _resolve_project propagates."""
    mock_params.command = 'scan-git'; mock_params.project_name = "NonExistent"; mock_params.scan_name = "S"; mock_params.git_url = "url"; mock_params.git_branch = "b"

    with pytest.raises(ProjectNotFoundError, match="Git project not found"):
        handlers.handle_scan_git(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called() # Should fail before resolving scan
    mock_exec_flow.assert_not_called() # Should fail before executing flow

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=ScanNotFoundError("Git scan not found"))
@patch('workbench_agent.handlers._execute_standard_scan_flow')
def test_handle_scan_git_scan_not_found(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ScanNotFoundError from _resolve_scan propagates."""
    mock_params.command = 'scan-git'; mock_params.project_name = "P"; mock_params.scan_name = "NonExistent"; mock_params.git_url = "url"; mock_params.git_branch = "b"
    mock_resolve_proj.return_value = "PC" # Project resolves successfully

    # Assume create_if_missing=False was passed to _resolve_scan somehow (e.g., different command context)
    # or that creation failed internally before raising ScanNotFoundError
    with pytest.raises(ScanNotFoundError, match="Git scan not found"):
        handlers.handle_scan_git(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once() # Resolve scan is called
    mock_exec_flow.assert_not_called() # Should fail before executing flow

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=CompatibilityError("Scan exists with different Git URL"))
@patch('workbench_agent.handlers._execute_standard_scan_flow')
def test_handle_scan_git_compatibility_error(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that CompatibilityError from _resolve_scan propagates."""
    mock_params.command = 'scan-git'; mock_params.project_name = "P"; mock_params.scan_name = "ExistingScan"; mock_params.git_url = "new_url"; mock_params.git_branch = "b"
    mock_resolve_proj.return_value = "PC"

    with pytest.raises(CompatibilityError, match="Scan exists with different Git URL"):
        handlers.handle_scan_git(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once() # Compatibility check happens within _resolve_scan
    mock_exec_flow.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=ApiError("API error during scan execution"))
def test_handle_scan_git_api_error(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ApiError from _execute_standard_scan_flow propagates."""
    mock_params.command = 'scan-git'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.git_url = "url"; mock_params.git_branch = "b"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(ApiError, match="API error during scan execution"):
        handlers.handle_scan_git(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_exec_flow.assert_called_once() # Error happens during execution

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=NetworkError("Network error during scan execution"))
def test_handle_scan_git_network_error(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that NetworkError from _execute_standard_scan_flow propagates."""
    mock_params.command = 'scan-git'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.git_url = "url"; mock_params.git_branch = "b"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(NetworkError, match="Network error during scan execution"):
        handlers.handle_scan_git(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_exec_flow.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=ProcessError("Scan failed on Workbench"))
def test_handle_scan_git_process_error(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ProcessError from _execute_standard_scan_flow propagates."""
    mock_params.command = 'scan-git'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.git_url = "url"; mock_params.git_branch = "b"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(ProcessError, match="Scan failed on Workbench"):
        handlers.handle_scan_git(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_exec_flow.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=ProcessTimeoutError("Scan timed out waiting"))
def test_handle_scan_git_process_timeout_error(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ProcessTimeoutError from _execute_standard_scan_flow propagates."""
    mock_params.command = 'scan-git'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.git_url = "url"; mock_params.git_branch = "b"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(ProcessTimeoutError, match="Scan timed out waiting"):
        handlers.handle_scan_git(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_exec_flow.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers._execute_standard_scan_flow', side_effect=Exception("Unexpected failure"))
def test_handle_scan_git_unexpected_error(mock_exec_flow, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that unexpected errors are wrapped in WorkbenchAgentError."""
    mock_params.command = 'scan-git'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.git_url = "url"; mock_params.git_branch = "b"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(WorkbenchAgentError, match="Unexpected failure"):
        handlers.handle_scan_git(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_exec_flow.assert_called_once()
