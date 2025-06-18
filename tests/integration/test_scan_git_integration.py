# tests/integration/test_scan_git_integration.py

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, mock_open

from workbench_cli.main import main

class TestScanGitIntegration:
    """Integration tests for the scan-git command"""

    def test_scan_git_success_flow_branch(self, mocker, capsys):
        """
        Integration test for a successful 'scan-git' command flow with git branch.
        """
        # Mock the resolver methods with correct class names
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock the core scan operations with correct method names
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.download_content_from_git', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.extract_archives', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.run_scan', return_value=None)
        
        # Mock the waiting operations with correct class names
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_git_clone',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 5.0))
        
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_archive_extraction',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 3.0))
        
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_scan_to_finish',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 10.0))
        
        # Mock status checkers with correct class name
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)
        
        # Mock git repository cleanup
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.remove_uploaded_content', return_value=None)

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan-git',
            '--project-name', 'TestGitProj',
            '--scan-name', 'TestGitScan',
            '--git-url', 'https://github.com/example/repo.git',
            '--git-branch', 'main'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 0, "Command should exit with success code"
        
        # Verify we got a success message in the output
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Workbench CLI finished successfully" in combined_output

    def test_scan_git_success_flow_tag(self, mocker, capsys):
        """
        Integration test for a successful 'scan-git' command flow with git tag.
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ002")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 124))
        
        # Mock scan operations
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.download_content_from_git', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.extract_archives', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.run_scan', return_value=None)
        
        # Mock waiting operations
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_git_clone',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 7.0))
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_archive_extraction',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 4.0))
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_scan_to_finish',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 12.0))
        
        # Mock status checkers
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)
        
        # Mock cleanup
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.remove_uploaded_content', return_value=None)

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan-git',
            '--project-name', 'TestGitProj',
            '--scan-name', 'TestGitTagScan',
            '--git-url', 'https://github.com/example/repo.git',
            '--git-tag', 'v1.0.0'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 0, "Scan-git with tag should succeed"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: scan-git" in combined_output

    def test_scan_git_with_dependency_analysis(self, mocker, capsys):
        """
        Test scan-git command with dependency analysis enabled.
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ003")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 125))
        
        # Mock scan operations
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.download_content_from_git', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.extract_archives', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.run_scan', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.start_dependency_analysis', return_value=None)
        
        # Mock waiting operations
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_git_clone',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 6.0))
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_archive_extraction',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 3.0))
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_scan_to_finish',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 15.0))
        
        # Mock status checkers
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)
        
        # Mock cleanup
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.remove_uploaded_content', return_value=None)

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan-git',
            '--project-name', 'TestGitProj',
            '--scan-name', 'TestGitScanDA',
            '--git-url', 'https://github.com/example/repo.git',
            '--git-branch', 'develop',
            '--run-dependency-analysis'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 0, "Scan-git with DA should succeed"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: scan-git" in combined_output

    def test_scan_git_dependency_analysis_only(self, mocker, capsys):
        """
        Test scan-git command with dependency analysis only (no KB scan).
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ004")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 126))
        
        # Mock scan operations - no KB scan for DA-only
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.download_content_from_git', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.extract_archives', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.start_dependency_analysis', return_value=None)
        
        # Mock waiting operations - no KB scan wait for DA-only
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_git_clone',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 4.0))
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_archive_extraction',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 2.0))
        
        # Mock status checkers
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)
        
        # Mock cleanup
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.remove_uploaded_content', return_value=None)

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan-git',
            '--project-name', 'TestGitProj',
            '--scan-name', 'TestGitDAOnly',
            '--git-url', 'https://github.com/example/repo.git',
            '--git-branch', 'main',
            '--dependency-analysis-only'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 0, "Scan-git DA-only should succeed"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: scan-git" in combined_output

    def test_scan_git_with_id_reuse(self, mocker, capsys):
        """
        Test scan-git command with ID reuse enabled.
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ005")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 127))
        
        # Mock ID reuse validation
        mocker.patch('workbench_cli.utilities.scan_target_validators.validate_reuse_source', return_value=None)
        
        # Mock scan operations
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.download_content_from_git', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.extract_archives', return_value=None)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.run_scan', return_value=None)
        
        # Mock waiting operations
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_git_clone',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 5.0))
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_archive_extraction',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 3.0))
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_scan_to_finish',
                    return_value=({"status": "FINISHED", "is_finished": "1"}, 8.0))
        
        # Mock status checkers
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)
        
        # Mock cleanup
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.remove_uploaded_content', return_value=None)

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan-git',
            '--project-name', 'TestGitProj',
            '--scan-name', 'TestGitReuseID',
            '--git-url', 'https://github.com/example/repo.git',
            '--git-branch', 'main',
            '--id-reuse',
            '--id-reuse-type', 'project',
            '--id-reuse-source', 'TestGitProj'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 0, "Scan-git with ID reuse should succeed"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: scan-git" in combined_output

    def test_scan_git_failure_invalid_git_url(self, mocker, capsys):
        """
        Test scan-git command with invalid git URL (should fail).
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ006")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 128))
        
        # Mock git clone failure
        from workbench_cli.exceptions import ProcessError
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.download_content_from_git', return_value=None)
        mocker.patch('workbench_cli.api.helpers.process_waiters.ProcessWaiters.wait_for_git_clone',
                    side_effect=ProcessError("Git clone failed: Repository not found"))
        
        # Mock status checkers
        mocker.patch('workbench_cli.api.helpers.scan_status_checkers.StatusCheckers.assert_process_can_start', 
                    return_value=None)

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan-git',
            '--project-name', 'TestGitProj',
            '--scan-name', 'TestGitFailScan',
            '--git-url', 'https://github.com/nonexistent/repo.git',
            '--git-branch', 'main'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 1, "Command should exit with error code"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Git clone failed" in combined_output

    def test_scan_git_failure_conflicting_refs(self, mocker, capsys):
        """
        Test scan-git command with conflicting git references (should fail validation).
        """
        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan-git',
            '--project-name', 'TestGitProj',
            '--scan-name', 'TestGitConflict',
            '--git-url', 'https://github.com/example/repo.git',
            '--git-branch', 'main',
            '--git-tag', 'v1.0.0'  # Both branch and tag specified - should fail
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 1, "Command should exit with validation error"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Cannot specify both" in combined_output or "mutually exclusive" in combined_output

    def test_scan_git_failure_missing_git_ref(self, mocker, capsys):
        """
        Test scan-git command with missing git reference (should fail validation).
        """
        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'scan-git',
            '--project-name', 'TestGitProj',
            '--scan-name', 'TestGitNoRef',
            '--git-url', 'https://github.com/example/repo.git'
            # Missing --git-branch, --git-tag, or --git-commit
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()
            assert return_code == 1, "Command should exit with validation error"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "must specify one of" in combined_output or "required" in combined_output 