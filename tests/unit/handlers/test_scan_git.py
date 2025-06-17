# tests/unit/handlers/test_scan_git.py

import pytest
from unittest.mock import MagicMock, patch, call

# Import handler and dependencies
from workbench_cli.handlers.scan_git import handle_scan_git, _get_project_and_scan_codes
from workbench_cli.exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ValidationError,
    ProcessError,
    ProcessTimeoutError,
    ConfigurationError,
    AuthenticationError,
    ScanExistsError,
    ProjectNotFoundError,
    ScanNotFoundError
)


class TestScanGitHandler:
    """Test cases for the scan-git handler."""

    @patch('workbench_cli.handlers.scan_git.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan_git.print_operation_summary')
    @patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_success_full_scan(self, mock_ensure_compat, mock_assert_idle, 
                                             mock_determine_scans, mock_print_summary, mock_fetch,
                                             mock_workbench, mock_params):
        """Tests successful git scan with both KB scan and dependency analysis."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.git_tag = None
        mock_params.git_commit = None
        mock_params.no_wait = False
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.return_value = None
        mock_workbench.wait_for_git_clone.return_value = ({}, 10.0)
        mock_workbench.remove_uploaded_content.return_value = True
        mock_workbench.wait_for_scan_to_finish.side_effect = [({}, 30.0), ({}, 15.0)]  # KB scan, then DA
        mock_workbench.get_pending_files.return_value = {}
        
        # Mock scan operations to run both KB and DA
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": True
        }

        # Execute the handler
        result = handle_scan_git(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.resolve_project.assert_called_once_with("GitProject", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with("GitScan", "GitProject", 
                                                          create_if_missing=True, params=mock_params)
        mock_workbench.download_content_from_git.assert_called_once_with('GIT_SCAN_CODE')
        mock_workbench.wait_for_git_clone.assert_called_once()
        mock_workbench.remove_uploaded_content.assert_called_once_with('GIT_SCAN_CODE', '.git/')
        mock_workbench.run_scan.assert_called_once()
        assert mock_workbench.wait_for_scan_to_finish.call_count == 2  # KB scan + DA
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.scan_git.print_operation_summary')
    @patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_no_wait(self, mock_ensure_compat, mock_assert_idle, 
                                   mock_determine_scans, mock_print_summary,
                                   mock_workbench, mock_params):
        """Tests git scan with no-wait mode."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.return_value = None
        mock_workbench.wait_for_git_clone.return_value = ({}, 10.0)
        mock_workbench.remove_uploaded_content.return_value = True
        
        # Mock scan operations to run both KB and DA
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": True
        }

        # Execute the handler
        result = handle_scan_git(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.run_scan.assert_called_once()
        # Should not wait for scans to finish in no-wait mode
        mock_workbench.wait_for_scan_to_finish.assert_not_called()
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.scan_git.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan_git.print_operation_summary')
    @patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_dependency_analysis_only(self, mock_ensure_compat, mock_assert_idle, 
                                                     mock_determine_scans, mock_print_summary, mock_fetch,
                                                     mock_workbench, mock_params):
        """Tests git scan with dependency analysis only."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.return_value = None
        mock_workbench.wait_for_git_clone.return_value = ({}, 10.0)
        mock_workbench.remove_uploaded_content.return_value = True
        mock_workbench.wait_for_scan_to_finish.return_value = ({}, 15.0)  # Only DA
        
        # Mock scan operations to run only DA
        mock_determine_scans.return_value = {
            "run_kb_scan": False,
            "run_dependency_analysis": True
        }

        # Execute the handler
        result = handle_scan_git(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.start_dependency_analysis.assert_called_once_with('GIT_SCAN_CODE', import_only=False)
        mock_workbench.run_scan.assert_not_called()  # Should not run KB scan
        mock_workbench.wait_for_scan_to_finish.assert_called_once_with(
            "DEPENDENCY_ANALYSIS", 'GIT_SCAN_CODE', mock_params.scan_number_of_tries, mock_params.scan_wait_time
        )
        mock_fetch.assert_called_once()
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.scan_git.print_operation_summary')
    @patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_dependency_analysis_only_no_wait(self, mock_ensure_compat, mock_assert_idle, 
                                                             mock_determine_scans, mock_print_summary,
                                                             mock_workbench, mock_params):
        """Tests git scan with dependency analysis only and no-wait mode."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.return_value = None
        mock_workbench.wait_for_git_clone.return_value = ({}, 10.0)
        mock_workbench.remove_uploaded_content.return_value = True
        
        # Mock scan operations to run only DA
        mock_determine_scans.return_value = {
            "run_kb_scan": False,
            "run_dependency_analysis": True
        }

        # Execute the handler
        result = handle_scan_git(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.start_dependency_analysis.assert_called_once_with('GIT_SCAN_CODE', import_only=False)
        mock_workbench.wait_for_scan_to_finish.assert_not_called()  # No wait mode
        mock_print_summary.assert_called_once()

    @patch('workbench_cli.handlers.scan_git.validate_reuse_source')
    @patch('workbench_cli.handlers.scan_git.print_operation_summary')
    @patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_with_id_reuse(self, mock_ensure_compat, mock_assert_idle, 
                                         mock_determine_scans, mock_print_summary, mock_validate_reuse,
                                         mock_workbench, mock_params):
        """Tests git scan with ID reuse enabled."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.no_wait = True
        mock_params.id_reuse = True
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.return_value = None
        mock_workbench.wait_for_git_clone.return_value = ({}, 10.0)
        mock_workbench.remove_uploaded_content.return_value = True
        mock_validate_reuse.return_value = ("project", "REUSE_CODE")
        
        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute the handler
        result = handle_scan_git(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_validate_reuse.assert_called_once_with(mock_workbench, mock_params)
        mock_workbench.run_scan.assert_called_once()
        # Check that ID reuse parameters were passed (positional args)
        call_args = mock_workbench.run_scan.call_args
        args = call_args[0]
        assert len(args) >= 8  # Should have at least 8 positional arguments
        assert args[7] is True  # id_reuse parameter (7th index)
        assert args[8] == "project"  # api_reuse_type parameter (8th index)
        assert args[9] == "REUSE_CODE"  # resolved_specific_code_for_reuse (9th index)

    @patch('workbench_cli.handlers.scan_git.validate_reuse_source')
    @patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_id_reuse_validation_fails(self, mock_ensure_compat, mock_assert_idle, 
                                                      mock_determine_scans, mock_validate_reuse,
                                                      mock_workbench, mock_params):
        """Tests git scan when ID reuse validation fails."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.no_wait = True
        mock_params.id_reuse = True
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.return_value = None
        mock_workbench.wait_for_git_clone.return_value = ({}, 10.0)
        mock_workbench.remove_uploaded_content.return_value = True
        mock_validate_reuse.side_effect = ValidationError("Reuse validation failed")
        
        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute the handler
        result = handle_scan_git(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_validate_reuse.assert_called_once_with(mock_workbench, mock_params)
        # Should continue with scan but without ID reuse
        mock_workbench.run_scan.assert_called_once()
        call_args = mock_workbench.run_scan.call_args
        args = call_args[0]
        assert args[7] is False  # ID reuse should be disabled (7th index)

    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_git_clone_fails(self, mock_ensure_compat, mock_assert_idle, 
                                           mock_workbench, mock_params):
        """Tests git scan when git clone fails."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.side_effect = ApiError("Git clone failed")

        # Execute and verify exception
        with pytest.raises(WorkbenchCLIError, match="Failed to clone Git repository"):
            handle_scan_git(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_project_not_found(self, mock_ensure_compat, mock_assert_idle,
                                              mock_workbench, mock_params):
        """Tests git scan when project resolution fails."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "NonExistent"
        mock_params.scan_name = "GitScan"
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.side_effect = ProjectNotFoundError("Project not found")

        # Execute and verify exception
        with pytest.raises(ProjectNotFoundError):
            handle_scan_git(mock_workbench, mock_params)

    @patch('workbench_cli.handlers.scan_git.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan_git.print_operation_summary')
    @patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_remove_git_dir_fails(self, mock_ensure_compat, mock_assert_idle, 
                                                 mock_determine_scans, mock_print_summary, mock_fetch,
                                                 mock_workbench, mock_params):
        """Tests git scan when removing .git directory fails."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.no_wait = True
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.return_value = None
        mock_workbench.wait_for_git_clone.return_value = ({}, 10.0)
        mock_workbench.remove_uploaded_content.side_effect = Exception("Remove failed")
        
        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute the handler - should continue despite remove failure
        result = handle_scan_git(mock_workbench, mock_params)
        
        # Verify the result and expected calls
        assert result is True
        mock_workbench.remove_uploaded_content.assert_called_once_with('GIT_SCAN_CODE', '.git/')
        mock_workbench.run_scan.assert_called_once()  # Should continue with scan

    @patch('workbench_cli.handlers.scan_git.fetch_display_save_results')
    @patch('workbench_cli.handlers.scan_git.print_operation_summary')
    @patch('workbench_cli.handlers.scan_git.determine_scans_to_run')
    @patch('workbench_cli.handlers.scan_git.assert_scan_is_idle')
    @patch('workbench_cli.handlers.scan_git.ensure_scan_compatibility')
    def test_handle_scan_git_kb_scan_timeout(self, mock_ensure_compat, mock_assert_idle, 
                                           mock_determine_scans, mock_print_summary, mock_fetch,
                                           mock_workbench, mock_params):
        """Tests git scan when KB scan times out."""
        # Configure params
        mock_params.command = 'scan-git'
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        mock_params.git_url = "https://github.com/example/repo.git"
        mock_params.git_branch = "main"
        mock_params.no_wait = False
        mock_params.id_reuse = False
        
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 123)
        mock_workbench.download_content_from_git.return_value = None
        mock_workbench.wait_for_git_clone.return_value = ({}, 10.0)
        mock_workbench.remove_uploaded_content.return_value = True
        mock_workbench.wait_for_scan_to_finish.side_effect = ProcessTimeoutError("Scan timed out")
        
        # Mock scan operations to run KB scan
        mock_determine_scans.return_value = {
            "run_kb_scan": True,
            "run_dependency_analysis": False
        }

        # Execute and verify exception
        with pytest.raises(ProcessTimeoutError):
            handle_scan_git(mock_workbench, mock_params)


class TestGetProjectAndScanCodes:
    """Test cases for the _get_project_and_scan_codes helper function."""
    
    def test_get_project_and_scan_codes_success(self, mock_workbench, mock_params):
        """Tests successful resolution of project and scan codes."""
        # Configure mocks
        mock_workbench.resolve_project.return_value = 'GIT_PROJ_CODE'
        mock_workbench.resolve_scan.return_value = ('GIT_SCAN_CODE', 456)
        mock_params.project_name = "GitProject"
        mock_params.scan_name = "GitScan"
        
        # Execute
        project_code, scan_code = _get_project_and_scan_codes(mock_workbench, mock_params)
        
        # Verify
        assert project_code == 'GIT_PROJ_CODE'
        assert scan_code == 'GIT_SCAN_CODE'
        mock_workbench.resolve_project.assert_called_once_with("GitProject", create_if_missing=True)
        mock_workbench.resolve_scan.assert_called_once_with("GitScan", "GitProject", 
                                                          create_if_missing=True, params=mock_params) 