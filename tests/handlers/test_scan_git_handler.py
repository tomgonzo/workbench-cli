# tests/handlers/test_scan_git_handler.py

import pytest
from unittest.mock import MagicMock, patch, call

# Import handler and dependencies
from workbench_agent.handlers.scan_git import handle_scan_git
from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    ProjectNotFoundError,
    ScanNotFoundError,
    CompatibilityError,
    ValidationError
)
# Import Workbench for type hinting in wait check
from workbench_agent.api import Workbench

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow')
@patch('workbench_agent.handlers.scan_git._fetch_display_save_results')
def test_handle_scan_git_success_branch(mock_fetch_results, mock_exec_flow, mock_assert_idle, 
                                       mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution of handle_scan_git using a branch."""
    # Setup mock_params for scan-git with branch
    mock_params.command = 'scan-git'
    mock_params.project_name = "GitProjBranch"
    mock_params.scan_name = "GitScanBranch"
    mock_params.git_url = "http://my.git/repo.git"
    mock_params.git_branch = "main"
    mock_params.git_tag = None
    mock_params.scan_number_of_tries = 10
    
    # Setup mock return values
    mock_resolve_proj.return_value = "GIT_PROJ_B_C"
    mock_resolve_scan.return_value = ("GIT_SCAN_B_C", 567)
    
    # Mock the git download and wait methods
    mock_workbench.download_content_from_git.return_value = True
    
    # Mock the execute_standard_scan_flow to return success with durations
    mock_exec_flow.return_value = (True, False, {"kb_scan": 120.5, "dependency_analysis": 0})

    # Call the handler
    handle_scan_git(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once_with(mock_workbench, "GitProjBranch", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, 
        scan_name="GitScanBranch", 
        project_name="GitProjBranch", 
        create_if_missing=True, 
        params=mock_params
    )
    mock_assert_idle.assert_called_once()
    
    # Assert git-related methods are called
    mock_workbench.download_content_from_git.assert_called_once_with("GIT_SCAN_B_C")
    mock_workbench.wait_for_git_clone.assert_called_once_with("GIT_SCAN_B_C", 10, 10)
    
    # Assert standard flow execution
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "GIT_PROJ_B_C", "GIT_SCAN_B_C", 567)
    mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "GIT_SCAN_B_C")

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow')
@patch('workbench_agent.handlers.scan_git._fetch_display_save_results')
def test_handle_scan_git_success_tag(mock_fetch_results, mock_exec_flow, mock_assert_idle,
                                    mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution of handle_scan_git using a tag."""
    # Setup mock_params for scan-git with tag
    mock_params.command = 'scan-git'
    mock_params.project_name = "GitProjTag"
    mock_params.scan_name = "GitScanTag"
    mock_params.git_url = "http://my.git/repo.git"
    mock_params.git_branch = None
    mock_params.git_tag = "v1.0.0" 
    mock_params.scan_number_of_tries = 10
    
    # Setup mock return values
    mock_resolve_proj.return_value = "GIT_PROJ_T_C"
    mock_resolve_scan.return_value = ("GIT_SCAN_T_C", 568)
    
    # Mock the git download and wait methods
    mock_workbench.download_content_from_git.return_value = True
    
    # Mock the execute_standard_scan_flow to return success with durations
    mock_exec_flow.return_value = (True, False, {"kb_scan": 130.0, "dependency_analysis": 0})

    # Call the handler
    handle_scan_git(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    
    # Assert git-related methods are called
    mock_workbench.download_content_from_git.assert_called_once_with("GIT_SCAN_T_C")
    mock_workbench.wait_for_git_clone.assert_called_once_with("GIT_SCAN_T_C", 10, 10)
    
    # Assert standard flow execution
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "GIT_PROJ_T_C", "GIT_SCAN_T_C", 568)
    mock_fetch_results.assert_called_once()

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow')
def test_handle_scan_git_download_start_fails(mock_exec_flow, mock_assert_idle, 
                                            mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure during the git download initiation API call."""
    # Setup mock_params
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Simulate API error during download initiation
    mock_workbench.download_content_from_git.side_effect = ApiError("Invalid Git URL")

    # Call the handler and verify exception
    with pytest.raises(WorkbenchAgentError, match="Failed to initiate Git clone: Invalid Git URL"):
        handle_scan_git(mock_workbench, mock_params)

    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.download_content_from_git.assert_called_once_with("SC")
    mock_workbench.wait_for_git_clone.assert_not_called() # Wait should not be called
    mock_exec_flow.assert_not_called() # Execute flow should not be called

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow')
def test_handle_scan_git_download_wait_fails(mock_exec_flow, mock_assert_idle, 
                                           mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests failure during the git download wait process."""
    # Setup mock_params
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.scan_number_of_tries = 5
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Mock the git download to succeed but wait to fail
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.side_effect = ProcessTimeoutError("Git clone timed out")

    # Call the handler and verify exception
    with pytest.raises(ProcessTimeoutError, match="Git clone timed out"):
        handle_scan_git(mock_workbench, mock_params)

    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.download_content_from_git.assert_called_once_with("SC")
    mock_workbench.wait_for_git_clone.assert_called_once_with("SC", 5, 10) 
    mock_exec_flow.assert_not_called() # Execute flow should not be called

@patch('workbench_agent.handlers.scan_git._resolve_project', side_effect=ProjectNotFoundError("Git project not found"))
def test_handle_scan_git_project_not_found(mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ProjectNotFoundError from _resolve_project propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "NonExistent"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    
    # Call the handler and verify exception
    with pytest.raises(ProjectNotFoundError, match="Git project not found"):
        handle_scan_git(mock_workbench, mock_params)
    
    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_workbench.download_content_from_git.assert_not_called()

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan', side_effect=ScanNotFoundError("Git scan not found"))
def test_handle_scan_git_scan_not_found(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ScanNotFoundError from _resolve_scan propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "NonExistent"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    
    # Call the handler and verify exception
    with pytest.raises(ScanNotFoundError, match="Git scan not found"):
        handle_scan_git(mock_workbench, mock_params)
    
    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_workbench.download_content_from_git.assert_not_called()

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan', side_effect=CompatibilityError("Scan exists with different Git URL"))
def test_handle_scan_git_compatibility_error(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that CompatibilityError from _resolve_scan propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "ExistingScan"
    mock_params.git_url = "new_url"
    mock_params.git_branch = "b"
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    
    # Call the handler and verify exception
    with pytest.raises(CompatibilityError, match="Scan exists with different Git URL"):
        handle_scan_git(mock_workbench, mock_params)
    
    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_workbench.download_content_from_git.assert_not_called()

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow', side_effect=ApiError("API error during scan execution"))
def test_handle_scan_git_api_error_in_exec(mock_exec_flow, mock_assert_idle, 
                                         mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ApiError from _execute_standard_scan_flow propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.scan_number_of_tries = 5
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True

    # Call the handler and verify exception
    with pytest.raises(ApiError, match="API error during scan execution"):
        handle_scan_git(mock_workbench, mock_params)

    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.download_content_from_git.assert_called_once()
    mock_workbench.wait_for_git_clone.assert_called_once()
    mock_exec_flow.assert_called_once() # Error happens during execution

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow', side_effect=NetworkError("Network error during scan execution"))
def test_handle_scan_git_network_error(mock_exec_flow, mock_assert_idle, 
                                     mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that NetworkError from _execute_standard_scan_flow propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.scan_number_of_tries = 5
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True

    # Call the handler and verify exception
    with pytest.raises(NetworkError, match="Network error during scan execution"):
        handle_scan_git(mock_workbench, mock_params)

    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.download_content_from_git.assert_called_once()
    mock_workbench.wait_for_git_clone.assert_called_once()
    mock_exec_flow.assert_called_once()

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow', side_effect=ProcessError("Scan failed on Workbench"))
def test_handle_scan_git_process_error(mock_exec_flow, mock_assert_idle, 
                                     mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ProcessError from _execute_standard_scan_flow propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.scan_number_of_tries = 5
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True

    # Call the handler and verify exception
    with pytest.raises(ProcessError, match="Scan failed on Workbench"):
        handle_scan_git(mock_workbench, mock_params)

    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.download_content_from_git.assert_called_once()
    mock_workbench.wait_for_git_clone.assert_called_once()
    mock_exec_flow.assert_called_once()

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow', side_effect=ProcessTimeoutError("Scan timed out waiting"))
def test_handle_scan_git_process_timeout_error(mock_exec_flow, mock_assert_idle, 
                                             mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ProcessTimeoutError from _execute_standard_scan_flow propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.scan_number_of_tries = 5
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True

    # Call the handler and verify exception
    with pytest.raises(ProcessTimeoutError, match="Scan timed out waiting"):
        handle_scan_git(mock_workbench, mock_params)

    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.download_content_from_git.assert_called_once()
    mock_workbench.wait_for_git_clone.assert_called_once()
    mock_exec_flow.assert_called_once()

@patch('workbench_agent.handlers.scan_git._resolve_project')
@patch('workbench_agent.handlers.scan_git._resolve_scan')
@patch('workbench_agent.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_agent.handlers.scan_git._execute_standard_scan_flow', side_effect=Exception("Unexpected failure"))
def test_handle_scan_git_unexpected_error(mock_exec_flow, mock_assert_idle, 
                                        mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that unexpected errors are wrapped in WorkbenchAgentError."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.scan_number_of_tries = 5
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True

    # Call the handler and verify exception
    with pytest.raises(WorkbenchAgentError, match="Unexpected failure"):
        handle_scan_git(mock_workbench, mock_params)

    # Verify expected calls
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_workbench.download_content_from_git.assert_called_once()
    mock_workbench.wait_for_git_clone.assert_called_once()
    mock_exec_flow.assert_called_once()
