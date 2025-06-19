# tests/integration/test_scan_git_integration.py

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, mock_open

from workbench_cli.main import main
from workbench_cli.exceptions import ProcessError

class TestScanGitIntegration:
    """Integration tests for the scan-git command"""

    def test_scan_git_success_flow_branch(self, mock_workbench_api, capsys):
        """
        Integration test for a successful 'scan-git' command flow with git branch.
        """
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
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Workbench CLI finished successfully" in combined_output

    def test_scan_git_success_flow_tag(self, mock_workbench_api, capsys):
        """
        Integration test for a successful 'scan-git' command flow with git tag.
        """
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

    def test_scan_git_with_dependency_analysis(self, mock_workbench_api, capsys):
        """
        Test scan-git command with dependency analysis enabled.
        """
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

    def test_scan_git_dependency_analysis_only(self, mock_workbench_api, capsys):
        """
        Test scan-git command with dependency analysis only (no KB scan).
        """
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

    def test_scan_git_with_id_reuse(self, mock_workbench_api, mocker, capsys):
        """
        Test scan-git command with ID reuse enabled.
        """
        mocker.patch('workbench_cli.utilities.scan_target_validators.validate_reuse_source', return_value=None)
        
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

    def test_scan_git_failure_invalid_git_url(self, mock_workbench_api, capsys):
        """
        Test scan-git command with invalid git URL (should fail).
        """
        mock_workbench_api.wait_for_git_clone.side_effect = ProcessError("Git clone failed: Repository not found")
        
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
        assert "failed" in combined_output.lower()

    def test_scan_git_failure_conflicting_refs(self, mock_workbench_api, capsys):
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
            '--git-tag', 'v1.0.0'
        ]

        with patch.object(sys, 'argv', args), pytest.raises(SystemExit) as e:
            main()
        
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_scan_git_failure_missing_git_ref(self, mock_workbench_api, capsys):
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
        ]

        with patch.object(sys, 'argv', args), pytest.raises(SystemExit) as e:
            main()

        assert e.type == SystemExit
        assert e.value.code == 2 