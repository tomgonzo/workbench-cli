# tests/integration/test_evaluate_gates_integration.py

import pytest
import sys
from unittest.mock import patch

from workbench_cli.main import main

class TestEvaluateGatesIntegration:
    """Integration tests for the evaluate-gates command"""

    def test_evaluate_gates_pass_no_issues(self, mocker, capsys):
        """
        Test evaluate-gates command when no issues are found (should pass).
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock get_pending_files to return no pending files (gates should pass)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.get_pending_files', 
                    return_value={})
        
        # Mock policy warnings check with correct method name
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.get_policy_warnings_counter', 
                    return_value={"policy_warnings_total": 0})
        
        # Mock vulnerability check with correct method name
        mocker.patch('workbench_cli.api.vulnerabilities_api.VulnerabilitiesAPI.list_vulnerabilities', 
                    return_value=[])

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'evaluate-gates',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScan'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()

        assert return_code == 0, "evaluate-gates should pass when no issues found"
        
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_fail_on_pending(self, mocker, capsys):
        """
        Test evaluate-gates command when pending files are found and --fail-on-pending is set.
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock get_pending_files to return pending files (should cause failure)
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.get_pending_files', 
                    return_value={"file1.cpp": {"status": "pending"}, "file2.h": {"status": "pending"}})

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'evaluate-gates',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScan',
            '--fail-on-pending'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()

        # Should fail due to pending files
        assert return_code != 0, "evaluate-gates should fail when pending files found and --fail-on-pending is set"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_fail_on_policy_warnings(self, mocker, capsys):
        """
        Test evaluate-gates command when policy warnings are found and --fail-on-policy is set.
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock get_pending_files to return no pending files
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.get_pending_files', 
                    return_value={})
        
        # Mock policy warnings check to return warnings
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.get_policy_warnings_counter', 
                    return_value={"policy_warnings_total": 2})

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'evaluate-gates',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScan',
            '--fail-on-policy'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()

        # Should fail due to policy warnings
        assert return_code != 0, "evaluate-gates should fail when policy warnings found and --fail-on-policy is set"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_fail_on_vulnerabilities(self, mocker, capsys):
        """
        Test evaluate-gates command when vulnerabilities are found and --fail-on-vuln-severity is set.
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock get_pending_files to return no pending files
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.get_pending_files', 
                    return_value={})
        
        # Mock policy warnings check to return no warnings
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.get_policy_warnings_counter', 
                    return_value={"policy_warnings_total": 0})
        
        # Mock vulnerability check to return high severity vulnerabilities
        mocker.patch('workbench_cli.api.vulnerabilities_api.VulnerabilitiesAPI.list_vulnerabilities', 
                    return_value=[
                        {"id": "CVE-2021-1234", "severity": "critical", "description": "Critical vulnerability"},
                        {"id": "CVE-2021-5678", "severity": "high", "description": "High severity vulnerability"}
                    ])

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'evaluate-gates',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScan',
            '--fail-on-vuln-severity', 'high'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()

        # Should fail due to high severity vulnerabilities
        assert return_code != 0, "evaluate-gates should fail when vulnerabilities found and --fail-on-vuln-severity is set"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_show_pending_files(self, mocker, capsys):
        """
        Test evaluate-gates command with --show-pending-files flag.
        """
        # Mock the resolver methods
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    return_value="PRJ001")
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_scan', 
                    return_value=("TSC", 123))
        
        # Mock get_pending_files to return some pending files
        mocker.patch('workbench_cli.api.scans_api.ScansAPI.get_pending_files', 
                    return_value={"file1.cpp": {"status": "pending", "path": "/src/file1.cpp"}})

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'evaluate-gates',
            '--project-name', 'TestProj',
            '--scan-name', 'TestScan',
            '--show-pending-files'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()

        # Should pass because --fail-on-pending is not set
        assert return_code == 0, "evaluate-gates should pass when --fail-on-pending is not set, even with pending files"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert "Command: evaluate-gates" in combined_output

    def test_evaluate_gates_project_not_found(self, mocker, capsys):
        """
        Test evaluate-gates command when project is not found (should fail).
        """
        # Mock resolver to raise ProjectNotFoundError
        from workbench_cli.exceptions import ProjectNotFoundError
        mocker.patch('workbench_cli.api.helpers.project_scan_resolvers.ResolveWorkbenchProjectScan.resolve_project', 
                    side_effect=ProjectNotFoundError("Project 'NonExistentProj' not found"))

        args = [
            'workbench-cli',
            '--api-url', 'http://dummy.com',
            '--api-user', 'test',
            '--api-token', 'token',
            'evaluate-gates',
            '--project-name', 'NonExistentProj',
            '--scan-name', 'TestScan'
        ]

        with patch.object(sys, 'argv', args):
            return_code = main()

        # Should fail due to project not found
        assert return_code != 0, "evaluate-gates should fail when project is not found"
        captured = capsys.readouterr()
        combined_output = captured.out + captured.err
        assert any(term in combined_output.lower() for term in ["not found", "error", "project"]) 