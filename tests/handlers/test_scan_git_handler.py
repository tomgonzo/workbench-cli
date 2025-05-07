# tests/handlers/test_scan_git_handler.py

import pytest
from unittest.mock import MagicMock, patch, call
import time

# Import handler and dependencies
from workbench_cli.handlers.scan_git import handle_scan_git
from workbench_cli.exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ProjectNotFoundError,
    ScanNotFoundError,
    CompatibilityError,
    ValidationError
)
# Import Workbench for type hinting in wait check
from workbench_cli.api import WorkbenchAPI

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git._fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git._print_operation_summary')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
def test_handle_scan_git_success_branch(mock_determine_scans, mock_print_summary, mock_fetch_results, 
                                      mock_assert_idle, mock_ensure_compatibility, mock_resolve_scan, 
                                      mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution of handle_scan_git using a branch."""
    # Setup mock_params for scan-git with branch
    mock_params.command = 'scan-git'
    mock_params.project_name = "GitProjBranch"
    mock_params.scan_name = "GitScanBranch"
    mock_params.git_url = "http://my.git/repo.git"
    mock_params.git_branch = "main"
    mock_params.git_tag = None
    mock_params.git_commit = None  # Ensure commit is None for branch test
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.show_licenses = True
    mock_params.show_components = True
    mock_params.show_vulnerabilities = True
    mock_params.show_dependencies = False
    mock_params.show_scan_metrics = False
    mock_params.show_policy_warnings = False
    mock_params.no_wait = False
    mock_params.output_format = "text"
    mock_params.output_file = None
    
    # Setup mock return values
    mock_resolve_proj.return_value = "GIT_PROJ_B_C"
    mock_resolve_scan.return_value = ("GIT_SCAN_B_C", 567)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock the git download and wait methods
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock the scan completion
    mock_workbench.run_scan.return_value = None
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 120.5)

    # Call the handler
    result = handle_scan_git(mock_workbench, mock_params)

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
    mock_ensure_compatibility.assert_called_once()
    
    # Assert git-related methods are called
    mock_workbench.download_content_from_git.assert_called_once_with("GIT_SCAN_B_C")
    mock_workbench.wait_for_git_clone.assert_called_once_with("GIT_SCAN_B_C", 10, mock_params.scan_wait_time)
    
    # Assert scan methods are called
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()
    mock_fetch_results.assert_called_once()
    assert result == True

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git._fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git._print_operation_summary')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
def test_handle_scan_git_success_tag(mock_determine_scans, mock_print_summary, mock_fetch_results, 
                                   mock_assert_idle, mock_ensure_compatibility, mock_resolve_scan, 
                                   mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution of handle_scan_git using a tag."""
    # Setup mock_params for scan-git with tag
    mock_params.command = 'scan-git'
    mock_params.project_name = "GitProjTag"
    mock_params.scan_name = "GitScanTag"
    mock_params.git_url = "http://my.git/repo.git"
    mock_params.git_branch = None
    mock_params.git_tag = "v1.0.0" 
    mock_params.git_commit = None  # Ensure commit is None for tag test
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.show_licenses = True
    mock_params.show_components = True
    mock_params.show_vulnerabilities = True
    mock_params.show_dependencies = False
    mock_params.show_scan_metrics = False
    mock_params.show_policy_warnings = False
    mock_params.no_wait = False
    mock_params.output_format = "text"
    mock_params.output_file = None
    
    # Setup mock return values
    mock_resolve_proj.return_value = "GIT_PROJ_T_C"
    mock_resolve_scan.return_value = ("GIT_SCAN_T_C", 568)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock the git download and wait methods
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock the scan completion
    mock_workbench.run_scan.return_value = None
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 130.0)

    # Call the handler
    result = handle_scan_git(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_assert_idle.assert_called_once()
    mock_ensure_compatibility.assert_called_once()
    
    # Assert git-related methods are called
    mock_workbench.download_content_from_git.assert_called_once_with("GIT_SCAN_T_C")
    mock_workbench.wait_for_git_clone.assert_called_once_with("GIT_SCAN_T_C", 10, mock_params.scan_wait_time)
    
    # Assert scan methods are called
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()
    mock_fetch_results.assert_called_once()
    assert result == True

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git._fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git._print_operation_summary')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
def test_handle_scan_git_success_commit(mock_determine_scans, mock_print_summary, mock_fetch_results, 
                                      mock_assert_idle, mock_ensure_compatibility, mock_resolve_scan, 
                                      mock_resolve_proj, mock_workbench, mock_params):
    """Tests successful execution of handle_scan_git using a commit."""
    # Setup mock_params for scan-git with commit
    mock_params.command = 'scan-git'
    mock_params.project_name = "GitProjCommit"
    mock_params.scan_name = "GitScanCommit"
    mock_params.git_url = "http://my.git/repo.git"
    mock_params.git_branch = None
    mock_params.git_tag = None
    mock_params.git_commit = "abc123def456"
    mock_params.scan_number_of_tries = 10
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.show_licenses = True
    mock_params.show_components = True
    mock_params.show_vulnerabilities = True
    mock_params.show_dependencies = False
    mock_params.show_scan_metrics = False
    mock_params.show_policy_warnings = False
    mock_params.no_wait = False
    mock_params.output_format = "text"
    mock_params.output_file = None
    
    # Setup mock return values
    mock_resolve_proj.return_value = "GIT_PROJ_C_C"
    mock_resolve_scan.return_value = ("GIT_SCAN_C_C", 569)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock the git download and wait methods
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock the scan completion
    mock_workbench.run_scan.return_value = None
    mock_workbench.wait_for_scan_to_finish.return_value = ({}, 125.0)

    # Call the handler
    result = handle_scan_git(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once_with(mock_workbench, "GitProjCommit", create_if_missing=True)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, 
        scan_name="GitScanCommit", 
        project_name="GitProjCommit", 
        create_if_missing=True, 
        params=mock_params
    )
    mock_assert_idle.assert_called_once()
    mock_ensure_compatibility.assert_called_once()
    
    # Assert git-related methods are called
    mock_workbench.download_content_from_git.assert_called_once_with("GIT_SCAN_C_C")
    mock_workbench.wait_for_git_clone.assert_called_once_with("GIT_SCAN_C_C", 10, mock_params.scan_wait_time)
    
    # Assert scan methods are called
    mock_workbench.assert_process_can_start.assert_called_once()
    mock_workbench.run_scan.assert_called_once()
    mock_workbench.wait_for_scan_to_finish.assert_called_once()
    mock_fetch_results.assert_called_once()
    assert result == True

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git._fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git._print_operation_summary')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
def test_handle_scan_git_process_timeout_error(mock_determine_scans, mock_print_summary, mock_fetch_results, 
                                             mock_assert_idle, mock_ensure_compatibility, mock_resolve_scan, 
                                             mock_resolve_proj, mock_workbench, mock_params):
    """Tests process timeout during scan execution."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    mock_params.scan_number_of_tries = 5
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.no_wait = False
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)
    mock_workbench.run_scan.return_value = None
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock process timeout during scan wait
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Scan timed out waiting")

    # Call the handler and verify exception
    with pytest.raises(ProcessTimeoutError, match="Scan timed out waiting"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
def test_handle_scan_git_unexpected_error(mock_determine_scans, mock_assert_idle, mock_ensure_compatibility,
                                         mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests unexpected error handling during scan execution."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    mock_params.scan_number_of_tries = 5
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.no_wait = False
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock unexpected error during scan
    mock_workbench.run_scan.side_effect = Exception("Unexpected failure")

    # Call the handler and verify exception
    with pytest.raises(WorkbenchCLIError, match="Error during KB scan: Unexpected failure"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
def test_handle_scan_git_api_error_in_exec(mock_determine_scans, mock_assert_idle, mock_ensure_compatibility,
                                         mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests API error during scan execution."""
    # Setup mock_params
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    mock_params.scan_number_of_tries = 5
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.no_wait = False
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock scan execution to fail
    mock_workbench.run_scan.side_effect = ApiError("API error during scan execution")

    # Call the handler and verify exception
    with pytest.raises(WorkbenchCLIError, match="Error during KB scan: API error during scan execution"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
def test_handle_scan_git_network_error(mock_determine_scans, mock_assert_idle, mock_ensure_compatibility,
                                     mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests network error during scan execution."""
    # Setup mock_params
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    mock_params.scan_number_of_tries = 5
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.no_wait = False
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock network error during scan
    mock_workbench.run_scan.side_effect = NetworkError("Network error during scan execution")

    # Call the handler and verify exception
    with pytest.raises(WorkbenchCLIError, match="Error during KB scan: Network error during scan execution"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
def test_handle_scan_git_process_error(mock_determine_scans, mock_assert_idle, mock_ensure_compatibility,
                                     mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests process error during scan execution."""
    # Setup mock_params
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    mock_params.scan_number_of_tries = 5
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    mock_params.autoid_file_licenses = False
    mock_params.autoid_file_copyrights = False
    mock_params.autoid_pending_ids = False
    mock_params.delta_scan = False
    mock_params.id_reuse = False
    mock_params.no_wait = False
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }
    
    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)
    mock_workbench.run_scan.return_value = None
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock process error during scan wait
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessError("Scan failed on Workbench")

    # Call the handler and verify exception
    with pytest.raises(ProcessError, match="Scan failed on Workbench"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
def test_handle_scan_git_download_wait_fails(mock_assert_idle, mock_ensure_compatibility, 
                                            mock_resolve_scan, mock_resolve_proj, 
                                            mock_workbench, mock_params):
    """Tests failure during the git download wait process."""
    # Setup mock_params
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    mock_params.scan_number_of_tries = 5
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Mock the git download to succeed but wait to fail
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.side_effect = ProcessTimeoutError("Git clone timed out")

    # Call the handler and verify exception
    with pytest.raises(ProcessTimeoutError, match="Git clone timed out"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan')
@patch('workbench_cli.handlers.scan_git._ensure_scan_compatibility')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
def test_handle_scan_git_download_start_fails(mock_assert_idle, mock_ensure_compatibility, 
                                             mock_resolve_scan, mock_resolve_proj, 
                                             mock_workbench, mock_params):
    """Tests failure during the git download initiation API call."""
    # Setup mock_params
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    mock_params.scan_wait_time = 5
    mock_params.limit = 10
    mock_params.sensitivity = "medium"
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    
    # Mock assert_process_can_start method (special handling needed for methods starting with 'assert')
    mock_workbench.assert_process_can_start = MagicMock(return_value=None)
    mock_workbench.remove_uploaded_content = MagicMock(return_value=True)
    
    # Simulate API error during download initiation
    mock_workbench.download_content_from_git.side_effect = ApiError("Invalid Git URL")

    # Call the handler and verify exception
    with pytest.raises(ApiError, match="Invalid Git URL"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project', side_effect=ProjectNotFoundError("Git project not found"))
def test_handle_scan_git_project_not_found(mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ProjectNotFoundError from _resolve_project propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "NonExistent"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    
    # Call the handler and verify exception
    with pytest.raises(ProjectNotFoundError, match="Git project not found"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan', side_effect=ScanNotFoundError("Git scan not found"))
def test_handle_scan_git_scan_not_found(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that ScanNotFoundError from _resolve_scan propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "NonExistent"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    
    # Call the handler and verify exception
    with pytest.raises(ScanNotFoundError, match="Git scan not found"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._resolve_project')
@patch('workbench_cli.handlers.scan_git._resolve_scan', side_effect=CompatibilityError("Scan exists with different Git URL"))
def test_handle_scan_git_compatibility_error(mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    """Tests that CompatibilityError from _resolve_scan propagates."""
    # Setup mock_params with required git url
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "ExistingScan"
    mock_params.git_url = "new_url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    
    # Setup mock return values
    mock_resolve_proj.return_value = "PC"
    
    # Call the handler and verify exception
    with pytest.raises(CompatibilityError, match="Scan exists with different Git URL"):
        handle_scan_git(mock_workbench, mock_params)
