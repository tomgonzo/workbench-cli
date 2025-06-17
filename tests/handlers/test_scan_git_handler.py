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
from .. import handlers

# Note: mock_workbench and mock_params fixtures are automatically available from conftest.py

@patch('workbench_cli.handlers.scan_git.fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git.print_operation_summary')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
@patch('workbench_cli.handlers.scan_git.wait_for_scan_completion', return_value=(True, True, {}))
@patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
def test_handle_scan_git_success(mock_assert_idle, mock_wait, mock_determine_scans, mock_summary, mock_fetch, mock_workbench, mock_params):
    """Tests a successful run of handle_scan_git."""
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
    mock_workbench.resolve_project.return_value = "GIT_PROJ_B_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_B_C", 567)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": True}
    
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
    result = handlers.scan_git.handle_scan_git(mock_workbench, mock_params)

    # Assertions
    mock_workbench.resolve_project.assert_called_once_with("GitProjBranch", create_if_missing=True)
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="GitScanBranch",
        project_name="GitProjBranch",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once()
    mock_workbench.scans.run_scan_from_git.assert_called_once()
    mock_wait.assert_called_once()
    mock_summary.assert_called_once()
    mock_fetch.assert_called_once()
    assert result == True

@patch('workbench_cli.handlers.scan_git.fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git.print_operation_summary')
@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
@patch('workbench_cli.handlers.scan_git.wait_for_scan_completion')
@patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
def test_handle_scan_git_no_wait(mock_assert_idle, mock_wait, mock_determine_scans, mock_summary, mock_fetch, mock_workbench, mock_params):
    """Tests the --no-wait flag functionality for scan-git."""
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
    mock_params.no_wait = True
    mock_params.output_format = "text"
    mock_params.output_file = None
    
    # Setup mock return values
    mock_workbench.resolve_project.return_value = "GIT_PROJ_B_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_B_C", 567)
    
    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {"run_kb_scan": True, "run_dependency_analysis": True}
    
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
    result = handlers.scan_git.handle_scan_git(mock_workbench, mock_params)

    # Assertions
    mock_workbench.resolve_project.assert_called_once_with("GitProjBranch", create_if_missing=True)
    mock_workbench.resolve_scan.assert_called_once_with(
        scan_name="GitScanBranch",
        project_name="GitProjBranch",
        create_if_missing=True,
        params=mock_params
    )
    mock_assert_idle.assert_called_once()
    mock_workbench.scans.run_scan_from_git.assert_called_once()
    mock_wait.assert_not_called()
    mock_summary.assert_called_once()
    mock_fetch.assert_not_called()
    assert result == True

@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
@patch('workbench_cli.handlers.scan_git._print_operation_summary')
@patch('workbench_cli.handlers.scan_git._fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_success_branch(mock_ensure_compatibility, mock_assert_idle, mock_fetch_results,
                                      mock_print_summary, mock_determine_scans,
                                      mock_workbench, mock_params):
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
    mock_workbench.resolve_project.return_value = "GIT_PROJ_B_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_B_C", 567)
    
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
    mock_workbench.resolve_project.assert_called_once_with("GitProjBranch", create_if_missing=True)
    mock_workbench.resolve_scan.assert_called_once_with(
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

@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
@patch('workbench_cli.handlers.scan_git._print_operation_summary')
@patch('workbench_cli.handlers.scan_git._fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_success_tag(mock_ensure_compatibility, mock_assert_idle, mock_fetch_results,
                                   mock_print_summary, mock_determine_scans,
                                   mock_workbench, mock_params):
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
    mock_workbench.resolve_project.return_value = "GIT_PROJ_T_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_T_C", 568)
    
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
    mock_workbench.resolve_project.assert_called_once()
    mock_workbench.resolve_scan.assert_called_once()
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

@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
@patch('workbench_cli.handlers.scan_git._print_operation_summary')
@patch('workbench_cli.handlers.scan_git._fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_success_commit(mock_ensure_compatibility, mock_assert_idle, mock_fetch_results,
                                      mock_print_summary, mock_determine_scans,
                                      mock_workbench, mock_params):
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
    mock_workbench.resolve_project.return_value = "GIT_PROJ_C_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_C_C", 569)
    
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
    mock_workbench.resolve_project.assert_called_once()
    mock_workbench.resolve_scan.assert_called_once()
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

@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
@patch('workbench_cli.handlers.scan_git._print_operation_summary')
@patch('workbench_cli.handlers.scan_git._fetch_display_save_results')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_process_timeout_error(mock_ensure_compatibility, mock_assert_idle, mock_fetch_results,
                                             mock_print_summary, mock_determine_scans,
                                             mock_workbench, mock_params):
    """Tests that ProcessTimeoutError from wait_for_scan_to_finish propagates."""
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
    mock_workbench.resolve_project.return_value = "GIT_PROJ_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_C", 777)
    
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
    mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Process timeout occurred")

    # Call the handler and verify exception
    with pytest.raises(ProcessTimeoutError, match="Process timeout occurred"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_unexpected_error(mock_ensure_compatibility, mock_assert_idle,
                                         mock_determine_scans, mock_workbench, mock_params):
    """Tests that a generic exception is caught and wrapped."""
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
    mock_workbench.resolve_project.return_value = "GIT_PROJ_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_C", 777)
    
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
    mock_workbench.run_scan.side_effect = Exception("A wild error appeared")

    # Call the handler and verify exception
    with pytest.raises(WorkbenchCLIError, match="A wild error appeared"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_api_error_in_exec(mock_ensure_compatibility, mock_assert_idle,
                                             mock_determine_scans, mock_workbench, mock_params):
    """Tests that ApiError from run_scan propagates as WorkbenchCLIError."""
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
    mock_workbench.resolve_project.return_value = "GIT_PROJ_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_C", 777)

    # Configure determine_scans_to_run
    mock_determine_scans.return_value = {
        "run_kb_scan": True,
        "run_dependency_analysis": False
    }

    # Mock git methods to succeed
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.return_value = ({}, 5.0)

    # Mock assert_process_can_start method
    mock_workbench.assert_process_can_start.return_value = None
    mock_workbench.remove_uploaded_content.return_value = True

    # Mock scan execution to fail with ApiError
    mock_workbench.run_scan.side_effect = ApiError("Scan execution failed")

    # Call the handler and verify it raises WorkbenchCLIError
    with pytest.raises(WorkbenchCLIError, match="Error during KB scan: Scan execution failed"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_network_error(mock_ensure_compatibility, mock_assert_idle, mock_workbench, mock_params):
    """Tests that NetworkError from wait_for_git_clone propagates."""
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

    # Setup mock return values
    mock_workbench.resolve_project.return_value = "GIT_PROJ_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_C", 777)

    # Mock git methods to fail
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.side_effect = NetworkError("Network error on clone")

    # Call the handler and verify exception
    with pytest.raises(NetworkError, match="Network error on clone"):
        handle_scan_git(mock_workbench, mock_params)

@patch('workbench_cli.handlers.scan_git._assert_scan_is_idle')
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_process_error(mock_ensure_compatibility, mock_assert_idle, mock_workbench, mock_params):
    """Tests that ProcessError from wait_for_git_clone propagates."""
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

    # Setup mock return values
    mock_workbench.resolve_project.return_value = "GIT_PROJ_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_C", 777)

    # Mock git methods to fail
    mock_workbench.download_content_from_git.return_value = True
    mock_workbench.wait_for_git_clone.side_effect = ProcessError("Clone process failed")

    # Call the handler and verify exception
    with pytest.raises(ProcessError, match="Clone process failed"):
        handle_scan_git(mock_workbench, mock_params)
        
@patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
def test_handle_scan_git_compatibility_error(mock_ensure_compatibility, mock_workbench, mock_params):
    """Tests CompatibilityError is raised for mismatched Git URL."""
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "S"
    mock_params.git_url = "url"
    mock_params.git_branch = "b"
    mock_params.git_tag = None
    mock_params.git_commit = None
    mock_workbench.resolve_project.return_value = "GIT_PROJ_C"
    mock_workbench.resolve_scan.return_value = ("GIT_SCAN_C", 777)
    mock_ensure_compatibility.side_effect = CompatibilityError("Scan exists with different Git URL")
    with pytest.raises(CompatibilityError, match="Scan exists with different Git URL"):
        handle_scan_git(mock_workbench, mock_params)

def test_handle_scan_git_project_not_found(mock_workbench, mock_params):
    """Tests ProjectNotFoundError is raised when project resolution fails."""
    mock_params.command = 'scan-git'
    mock_params.project_name = "NonExistent"
    mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Git project not found")
    with pytest.raises(ProjectNotFoundError, match="Git project not found"):
        handle_scan_git(mock_workbench, mock_params)

def test_handle_scan_git_scan_not_found(mock_workbench, mock_params):
    """Tests ScanNotFoundError is raised when scan resolution fails."""
    mock_params.command = 'scan-git'
    mock_params.project_name = "P"
    mock_params.scan_name = "NonExistent"
    mock_workbench.resolve_project.return_value = "PC"
    mock_workbench.resolve_scan.side_effect = ScanNotFoundError("Git scan not found")
    with pytest.raises(ScanNotFoundError, match="Git scan not found"):
        handle_scan_git(mock_workbench, mock_params)
